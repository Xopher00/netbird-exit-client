package ech

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/net/doh"
)

// echConfig builds one ECHConfig (draft-ietf-tls-esni-18): DHKEM(X25519), HKDF-SHA256, AES-128-GCM.
func echConfig(t *testing.T) (config, list, private []byte) {
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
	c = append(c, byte(len("public.example")))
	c = append(c, "public.example"...)
	c = append(c, 0x00, 0x00) // extensions
	config = binary.BigEndian.AppendUint16([]byte{0xfe, 0x0d}, uint16(len(c)))
	config = append(config, c...)
	list = binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	list = append(list, config...)
	return config, list, key.Bytes()
}

// fakeLookup answers every name with 127.0.0.1 and the given key (none for nil).
func fakeLookup(t *testing.T, key []byte) {
	old := lookup
	lookup = func(context.Context, doh.DialFunc, string) (doh.Entry, error) {
		return doh.Entry{IPs: []string{"127.0.0.1"}, ECH: key}, nil
	}
	t.Cleanup(func() { lookup = old })
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

func dial(t *testing.T, addr string, pool *x509.CertPool, required bool) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return DialTLS(ctx, (&net.Dialer{}).DialContext, addr, "", &tls.Config{RootCAs: pool}, required)
}

// A published key is used for any host, not only Hopper's own.
func TestAKeyGivesECH(t *testing.T) {
	for _, required := range []bool{true, false} {
		config, list, priv := echConfig(t)
		fakeLookup(t, list)
		addr, pool, _ := target(t, []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: priv}})
		c, err := dial(t, addr, pool, required)
		if err != nil {
			t.Fatal(err)
		}
		if !c.(*tls.Conn).ConnectionState().ECHAccepted {
			t.Fatalf("ECH not used, required %t", required)
		}
		c.Close()
	}
}

// A host that publishes no key still connects, with plain TLS.
func TestNoKeyConnectsWithPlainTLS(t *testing.T) {
	fakeLookup(t, nil)
	addr, pool, conns := target(t, nil)
	c, err := dial(t, addr, pool, false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.(*tls.Conn).ConnectionState().ECHAccepted || conns.Load() != 1 {
		t.Fatal("want one plain TLS connection")
	}
}

// Hopper's own hosts are never dialled without a key: the name would be sent in clear.
func TestNoPublishedKeyRefusesBeforeConnecting(t *testing.T) {
	fakeLookup(t, nil)
	addr, pool, conns := target(t, nil)
	if _, err := dial(t, addr, pool, true); err == nil || !strings.Contains(err.Error(), "publishes no ECH key") {
		t.Fatalf("want refusal, got %v", err)
	}
	if n := conns.Load(); n != 0 {
		t.Fatalf("the server received %d connections; the name may have been sent", n)
	}
}
