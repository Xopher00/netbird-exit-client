package doh

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeResolver answers HTTPS with the key when given and A 127.0.0.1 for every name.
func fakeResolver(t *testing.T, key []byte) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q dns.Msg
		if r.Method != http.MethodPost || q.Unpack(body) != nil || q.Id != 0 {
			http.Error(w, "want a POST with id 0", 400)
			return
		}
		m := new(dns.Msg)
		m.SetReply(&q)
		qn := q.Question[0]
		hdr := dns.RR_Header{Name: qn.Name, Class: dns.ClassINET, Ttl: 300, Rrtype: qn.Qtype}
		switch {
		case qn.Name == "nothing.example.":
			m.Rcode = dns.RcodeNameError
		case qn.Qtype == dns.TypeHTTPS:
			h := &dns.HTTPS{SVCB: dns.SVCB{Hdr: hdr, Priority: 1, Target: "."}}
			if key != nil {
				h.Value = []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: key}}
			}
			m.Answer = append(m.Answer, h)
		case qn.Qtype == dns.TypeA:
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
	cache = map[string]Entry{}
	mu.Unlock()
	t.Cleanup(func() { resolvers, dohRoots = oldR, oldRoots })
}

var plain = (&net.Dialer{}).DialContext

func TestLookupGivesAddressesAndKey(t *testing.T) {
	fakeResolver(t, []byte{1, 2, 3})
	e, err := Lookup(context.Background(), plain, "any.example")
	if err != nil || e.KeyErr != nil || len(e.IPs) != 1 || e.IPs[0] != "127.0.0.1" || string(e.ECH) != "\x01\x02\x03" {
		t.Fatalf("got %+v, %v", e, err)
	}
}

// With every resolver failing there is no answer: the name never goes to the network's own DNS.
func TestNoResolverNoAnswer(t *testing.T) {
	fakeResolver(t, nil)
	resolvers = []string{"https://127.0.0.1:1/dns-query"}
	if _, err := Lookup(context.Background(), plain, "any.example"); err == nil || !strings.Contains(err.Error(), "dns over https") {
		t.Fatalf("want the lookup's failure, got %v", err)
	}
}

// NXDOMAIN is an answer the app must get, with the id it asked with.
func TestExchangeKeepsNXDOMAINAndTheID(t *testing.T) {
	fakeResolver(t, nil)
	m := new(dns.Msg)
	m.SetQuestion("nothing.example.", dns.TypeA)
	m.Id = 4242
	r, err := Exchange(context.Background(), client(plain, true), resolvers[0], m)
	if err != nil || r.Rcode != dns.RcodeNameError || r.Id != 4242 {
		t.Fatalf("got %v, %v", r, err)
	}
}

// Go's resolver gets its answers over DNS over HTTPS through Resolver.
func TestResolverAnswersOverDoH(t *testing.T) {
	fakeResolver(t, nil)
	ips, err := Resolver(plain).LookupHost(context.Background(), "any.example")
	if err != nil || len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("got %v, %v", ips, err)
	}
}
