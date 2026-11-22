// Package doh looks names up over DNS over HTTPS, never through a network's own resolver, and forwards DNS messages
// the same way.
package doh

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/util/embeddedroots"
)

// Cloudflare's and AdGuard's unfiltered resolvers, reached by address: a name would need a plain lookup first. Two
// providers, as nothing falls back to the network's DNS. A variable for tests.
var resolvers = []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query", "https://94.140.14.140/dns-query"}

// For tests: the resolvers' roots.
var dohRoots *x509.CertPool

type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Entry is a name's addresses and ECH key. KeyErr is the HTTPS lookup's failure: without its answer, whether a key
// exists is unknown.
type Entry struct {
	IPs    []string
	ECH    []byte
	KeyErr error
	until  time.Time
}

var (
	mu    sync.Mutex
	cache = map[string]Entry{}
)

// Roots are the system's roots, or NetBird's own where the system has none.
func Roots() *x509.CertPool {
	if pool, err := x509.SystemCertPool(); err == nil && pool != nil {
		return pool
	}
	return embeddedroots.Get()
}

// client is for the resolvers; keep holds connections open for a while, so a lookup is not a TLS handshake each time.
func client(dial DialFunc, keep bool) *http.Client {
	t := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: cmp.Or(dohRoots, Roots()), MinVersion: tls.VersionTLS12}}
	if keep {
		t.MaxIdleConnsPerHost, t.IdleConnTimeout = 4, 30*time.Second
	} else {
		t.DisableKeepAlives = true
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: t}
}

// Lookup gives host's addresses and ECH key, cached by their TTL (at least 60 s).
func Lookup(ctx context.Context, dial DialFunc, host string) (Entry, error) {
	mu.Lock()
	e, ok := cache[host]
	mu.Unlock()
	if ok && time.Now().Before(e.until) {
		return e, nil
	}
	return entryOf(host, askAll(ctx, dial, host, []uint16{dns.TypeHTTPS, dns.TypeA, dns.TypeAAAA}))
}

// SetKey keeps the key a server sent back for host in place of the published one.
func SetKey(host string, key []byte) {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := cache[host]; ok {
		e.ECH = key
		cache[host] = e
	}
}

type result struct {
	rrs []dns.RR
	ttl uint32
	err error
}

func askAll(ctx context.Context, dial DialFunc, host string, types []uint16) []result {
	c := client(dial, false)
	results := make([]result, len(types))
	var wg sync.WaitGroup
	for i, t := range types {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rrs, ttl, err := query(ctx, c, host, t)
			results[i] = result{rrs, ttl, err}
		}()
	}
	wg.Wait()
	return results
}

// entryOf reads the HTTPS, A and AAAA answers. Without the HTTPS answer the entry serves this dial only.
func entryOf(host string, results []result) (Entry, error) {
	e, ttl := Entry{KeyErr: results[0].err}, uint32(3600)
	if e.KeyErr == nil {
		e.ECH, ttl = echOf(results[0].rrs), results[0].ttl
	}
	ips, ttl, last := ipsOf(results[1:], ttl)
	if len(ips) == 0 {
		return Entry{}, cmp.Or(last, fmt.Errorf("%s has no address in DNS", host))
	}
	e.IPs, e.until = ips, time.Now().Add(time.Duration(max(ttl, 60))*time.Second)
	if e.KeyErr == nil {
		mu.Lock()
		cache[host] = e
		mu.Unlock()
	}
	return e, nil
}

// ipsOf collects the A then AAAA addresses of the answered lookups, the smallest TTL starting from ttl, and the last
// lookup's error.
func ipsOf(results []result, ttl uint32) (ips []string, minTTL uint32, last error) {
	var v4, v6 []string
	for _, r := range results {
		if r.err != nil {
			last = r.err
			continue
		}
		ttl = min(ttl, r.ttl)
		for _, rr := range r.rrs {
			switch a := rr.(type) {
			case *dns.A:
				v4 = append(v4, a.A.String())
			case *dns.AAAA:
				v6 = append(v6, a.AAAA.String())
			}
		}
	}
	return append(v4, v6...), ttl, last
}

func echOf(rrs []dns.RR) (ech []byte) {
	for _, rr := range rrs {
		if h, ok := rr.(*dns.HTTPS); ok {
			for _, kv := range h.Value {
				if c, ok := kv.(*dns.SVCBECHConfig); ok {
					ech = c.ECH
				}
			}
		}
	}
	return ech
}

// query returns the records of the first successful answer and their smallest TTL.
func query(ctx context.Context, c *http.Client, host string, qtype uint16) ([]dns.RR, uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	r, err := first(ctx, c, m)
	if err != nil {
		return nil, 0, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("dns over https: %s for %s", dns.RcodeToString[r.Rcode], host)
	}
	ttl := uint32(3600)
	for _, rr := range r.Answer {
		ttl = min(ttl, rr.Header().Ttl)
	}
	return r.Answer, ttl, nil
}

// Resolve asks the resolvers m's question over sockets from dial and returns the first answer, NXDOMAIN included.
func Resolve(ctx context.Context, dial DialFunc, m *dns.Msg) (*dns.Msg, error) {
	return first(ctx, client(dial, false), m)
}

// first asks every resolver at once, because a network can block one of them and waiting it out would cost the
// client's whole timeout. A SERVFAIL or REFUSED counts as no answer while another resolver may still give one.
func first(ctx context.Context, c *http.Client, m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		r   *dns.Msg
		err error
	}
	answers := make(chan answer, len(resolvers))
	for _, url := range resolvers {
		go func() {
			r, err := Exchange(ctx, c, url, m)
			if err == nil && r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
				err = fmt.Errorf("doh %s: %s", url, dns.RcodeToString[r.Rcode])
			}
			answers <- answer{r, err}
		}()
	}
	var last error
	for range resolvers {
		a := <-answers
		if a.err == nil {
			return a.r, nil
		}
		last = a.err
	}
	return nil, fmt.Errorf("dns over https for %s: %w", questionName(m), last)
}

func questionName(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return "no question"
	}
	return m.Question[0].Name
}

// Exchange sends one DNS message to a DNS-over-HTTPS server (RFC 8484, POST) and returns its answer whatever its rcode,
// with m's own id: the query goes with id 0, as the RFC asks.
func Exchange(ctx context.Context, c *http.Client, url string, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s: status %d %v", url, resp.StatusCode, err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	r.Id = m.Id
	return r, nil
}

// Forwarder sends DNS messages to the DNS-over-HTTPS service at a resolver's own address over kept connections. A dead
// connection fails one request and is dropped.
type Forwarder struct{ c *http.Client }

func NewForwarder(dial DialFunc) *Forwarder { return &Forwarder{c: client(dial, true)} }

// Forward sends m to https://<server>/dns-query; the server's certificate must name the address.
func (f *Forwarder) Forward(ctx context.Context, server netip.Addr, m *dns.Msg) (*dns.Msg, error) {
	return Exchange(ctx, f.c, "https://"+netip.AddrPortFrom(server, 443).String()+"/dns-query", m)
}

// Resolver is a net.Resolver whose every question goes to the resolvers over DNS over HTTPS, over sockets from dial.
func Resolver(dial DialFunc) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return &dohConn{dial: dial}, nil
	}}
}

// dohConn is the stream Go's resolver writes a query to and reads its answer from, both with a two-byte length (RFC
// 1035, 4.2.2): Go uses that framing for any connection that is not a PacketConn.
type dohConn struct {
	dial     DialFunc
	in, out  bytes.Buffer
	deadline time.Time
}

func (c *dohConn) Write(b []byte) (int, error) {
	c.in.Write(b)
	raw := c.in.Bytes()
	if len(raw) < 2 {
		return len(b), nil
	}
	n := 2 + (int(raw[0])<<8 | int(raw[1]))
	if len(raw) < n {
		return len(b), nil
	}
	m := new(dns.Msg)
	err := m.Unpack(raw[2:n])
	c.in.Next(n)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	if !c.deadline.IsZero() {
		ctx, cancel = context.WithDeadline(context.Background(), c.deadline)
	}
	defer cancel()
	r, err := Resolve(ctx, c.dial, m)
	if err != nil {
		return 0, err
	}
	wire, err := r.Pack()
	if err != nil {
		return 0, err
	}
	c.out.Write([]byte{byte(len(wire) >> 8), byte(len(wire))})
	c.out.Write(wire)
	return len(b), nil
}

func (c *dohConn) Read(b []byte) (int, error) {
	if c.out.Len() == 0 {
		return 0, io.EOF
	}
	return c.out.Read(b)
}

func (c *dohConn) Close() error                       { return nil }
func (c *dohConn) LocalAddr() net.Addr                { return dohAddr{} }
func (c *dohConn) RemoteAddr() net.Addr               { return dohAddr{} }
func (c *dohConn) SetDeadline(t time.Time) error      { c.deadline = t; return nil }
func (c *dohConn) SetReadDeadline(time.Time) error    { return nil }
func (c *dohConn) SetWriteDeadline(t time.Time) error { c.deadline = t; return nil }

type dohAddr struct{}

func (dohAddr) Network() string { return "doh" }
func (dohAddr) String() string  { return "dns over https" }
