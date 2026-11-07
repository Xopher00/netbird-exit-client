package ech

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// echConfig builds one ECHConfig (draft-ietf-tls-esni-18): DHKEM(X25519), HKDF-SHA256, AES-128-GCM.
func echConfig(t *testing.T) (config, list, private []byte) {
	return echConfigFor(t, "public.example")
}

func echConfigFor(t *testing.T, name string) (config, list, private []byte) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().Bytes()
	var c []byte
	c = append(c, 1)          // config_id
	c = append(c, 0x00, 0x20) // kem_id
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = append(c, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01) // one suite: HKDF-SHA256, AES-128-GCM
	c = append(c, 0)                                  // maximum_name_length
	c = append(c, byte(len(name)))
	c = append(c, name...)
	c = append(c, 0x00, 0x00) // extensions
	config = binary.BigEndian.AppendUint16([]byte{0xfe, 0x0d}, uint16(len(c)))
	config = append(config, c...)
	list = binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	list = append(list, config...)
	return config, list, key.Bytes()
}

// fakeDoH answers HTTPS (with the ECH list when given) and A 127.0.0.1 for every name.
func fakeDoH(t *testing.T, list []byte) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q dns.Msg
		if err := q.Unpack(body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		m := new(dns.Msg)
		m.SetReply(&q)
		qn := q.Question[0]
		hdr := dns.RR_Header{Name: qn.Name, Class: dns.ClassINET, Ttl: 300, Rrtype: qn.Qtype}
		switch qn.Qtype {
		case dns.TypeHTTPS:
			h := &dns.HTTPS{SVCB: dns.SVCB{Hdr: hdr, Priority: 1, Target: "."}}
			if list != nil {
				h.Value = []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: list}}
			}
			m.Answer = append(m.Answer, h)
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1)})
		}
		out, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	oldR, oldRoots := resolvers, dohRoots
	resolvers, dohRoots = []string{srv.URL + "/dns-query"}, pool
	mu.Lock()
	cache = map[string]entry{}
	mu.Unlock()
	t.Cleanup(func() { resolvers, dohRoots = oldR, oldRoots })
}

// target is a TLS server for example.com that counts the connections it receives.
func target(t *testing.T, keys []tls.EncryptedClientHelloKey) (addr string, pool *x509.CertPool, conns *atomic.Int32) {
	conns = new(atomic.Int32)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.TLS = &tls.Config{EncryptedClientHelloKeys: keys}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool = x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return net.JoinHostPort("example.com", port), pool, conns
}

func dial(t *testing.T, addr string, pool *x509.CertPool) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := &net.Dialer{}
	return DialTLS(ctx, d.DialContext, addr, "", &tls.Config{RootCAs: pool})
}

func TestAcceptedECHConnects(t *testing.T) {
	config, list, priv := echConfig(t)
	fakeDoH(t, list)
	addr, pool, _ := target(t, []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: priv}})
	c, err := dial(t, addr, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.(*tls.Conn).ConnectionState().ECHAccepted {
		t.Fatal("ECH not accepted")
	}
}

// A retry after a key change, dialled at a literal address, goes to that address with the new key and leaves the
// name's cached addresses and key as DNS published them.
func TestARetryAtALiteralAddressLeavesTheCacheAlone(t *testing.T) {
	_, oldList, _ := echConfigFor(t, "example.com")
	newConfig, _, newPriv := echConfigFor(t, "example.com")
	fakeDoH(t, oldList)
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("no 127.0.0.2 on this machine:", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Listener.Close()
	srv.Listener = l
	var conns atomic.Int32
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.TLS = &tls.Config{EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: newConfig, PrivateKey: newPriv, SendAsRetry: true}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := &net.Dialer{}
	c, err := DialTLS(ctx, d.DialContext, l.Addr().String(), "example.com", &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if n := conns.Load(); n != 2 {
		t.Fatalf("the literal address got %d connections, want 2 (the rejected one and the retry)", n)
	}
	mu.Lock()
	e := cache["example.com"]
	mu.Unlock()
	if len(e.ips) != 1 || e.ips[0] != "127.0.0.1" {
		t.Fatalf("cached addresses %v, want the DNS answer [127.0.0.1]", e.ips)
	}
	if string(e.ech) != string(oldList) {
		t.Fatal("a literal address's retry key replaced the name's published key")
	}
}

func TestNoPublishedKeyRefusesBeforeConnecting(t *testing.T) {
	fakeDoH(t, nil)
	addr, pool, conns := target(t, nil)
	if _, err := dial(t, addr, pool); err == nil || !strings.Contains(err.Error(), "publishes no ECH key") {
		t.Fatalf("want refusal, got %v", err)
	}
	if n := conns.Load(); n != 0 {
		t.Fatalf("the server received %d connections; the name may have been sent", n)
	}
}

func TestServerWithoutECHIsRefused(t *testing.T) {
	_, list, _ := echConfig(t)
	fakeDoH(t, list)
	addr, pool, _ := target(t, nil)
	if c, err := dial(t, addr, pool); err == nil {
		c.Close()
		t.Fatal("connected without ECH")
	}
}

type countedConn struct {
	net.Conn
	closed *atomic.Int32
}

func (c countedConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

func TestLookupLeavesNoConnectionOpen(t *testing.T) {
	_, list, _ := echConfig(t)
	fakeDoH(t, list)
	var opened, closed atomic.Int32
	d := &net.Dialer{}
	counting := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		opened.Add(1)
		return countedConn{c, &closed}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := lookup(ctx, counting, "example.com"); err != nil {
		t.Fatal(err)
	}
	limit := time.Now().Add(3 * time.Second)
	for closed.Load() < opened.Load() && time.Now().Before(limit) {
		time.Sleep(10 * time.Millisecond)
	}
	if o, c := opened.Load(), closed.Load(); o == 0 || c < o {
		t.Fatalf("%d connections opened, %d closed", o, c)
	}
}

func TestOnMatchesTheHostLoosely(t *testing.T) {
	t.Setenv(EnvHost, "Vpn.Example.dev.")
	for _, h := range []string{"vpn.example.dev", "VPN.EXAMPLE.DEV."} {
		if !On(h) {
			t.Errorf("On(%q) = false", h)
		}
	}
	if On("other.example.dev") {
		t.Error("On matched another host")
	}
	t.Setenv(EnvHost, "")
	if On("vpn.example.dev") {
		t.Error("On with no host set")
	}
}
