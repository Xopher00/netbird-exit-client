// Package ech connects to Hopper's own hosts (NB_ECH_HOST, comma-separated) with Encrypted Client Hello after a DNS over
// HTTPS lookup, so the name is in neither DNS nor the TLS handshake. Other hosts use DialDoH.
package ech

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/util/embeddedroots"
)

const EnvHost = "NB_ECH_HOST"

// Cloudflare's resolver, reached by address: a name would need a plain lookup first. A variable for tests.
var resolvers = []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"}

// For tests: the DoH client's roots.
var dohRoots *x509.CertPool

type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type entry struct {
	ips   []string
	ech   []byte
	until time.Time
}

var (
	mu    sync.Mutex
	cache = map[string]entry{}
)

// On reports whether connections to host must use ECH.
func On(host string) bool {
	host = strings.TrimSuffix(host, ".")
	for _, want := range strings.Split(os.Getenv(EnvHost), ",") {
		want = strings.TrimSuffix(strings.TrimSpace(want), ".")
		if want != "" && strings.EqualFold(want, host) {
			return true
		}
	}
	return false
}

func roots() *x509.CertPool {
	if pool, err := x509.SystemCertPool(); err == nil && pool != nil {
		return pool
	}
	return embeddedroots.Get()
}

// TLSDialer returns a DialTLSContext for an http.Transport: ECH for the ECH host, plain TLS for any other.
// name, when set, is the TLS server name the caller expects regardless of the address dialled.
func TLSDialer(dial DialFunc, name string, base *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		server := name
		if server == "" {
			server = host
		}
		if On(server) || On(host) {
			return DialTLS(ctx, dial, addr, server, base)
		}
		return DialDoH(ctx, dial, addr, server, base)
	}
}

// DialDoH connects with ordinary TLS to an address from DNS over HTTPS. Only when every lookup fails does the dialer
// resolve the name itself, so an ECH host must use DialTLS, which never falls back.
func DialDoH(ctx context.Context, dial DialFunc, addr, name string, base *tls.Config) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = host
	}
	var raw net.Conn
	if net.ParseIP(host) != nil {
		raw, err = dial(ctx, "tcp", addr)
	} else if raw, err = dialAny(ctx, dial, host, port); err != nil {
		raw, err = dial(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	cfg := base.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = name
	}
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

func dialAny(ctx context.Context, dial DialFunc, host, port string) (net.Conn, error) {
	ips, err := addresses(ctx, dial, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		raw, err := dial(ctx, "tcp", net.JoinHostPort(ip, port))
		if err == nil {
			return raw, nil
		}
		last = err
	}
	return nil, last
}

// DialTLS connects to addr with ECH for name, at an address from DNS over HTTPS unless addr already holds one.
// It refuses when no ECH configuration is published or ECH is not accepted: the name must never be sent in clear.
func DialTLS(ctx context.Context, dial DialFunc, addr, name string, base *tls.Config) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = host
	}
	e, err := lookup(ctx, dial, name)
	if err != nil {
		return nil, err
	}
	// A literal address is for this dial only: the cache keeps the name's DNS addresses, and a key that front sends
	// back is not cached for the name either, since it may not be the front DNS names.
	literal := net.ParseIP(host) != nil
	at := e
	if literal {
		at.ips = []string{host}
	}
	conn, err := handshake(ctx, dial, name, port, at, base)
	// A server whose key changed answers with the new one; one retry with it.
	var rejected *tls.ECHRejectionError
	if errors.As(err, &rejected) && len(rejected.RetryConfigList) > 0 {
		at.ech = rejected.RetryConfigList
		if !literal {
			e.ech = at.ech
			store(name, e)
		}
		conn, err = handshake(ctx, dial, name, port, at, base)
	}
	return conn, err
}

func handshake(ctx context.Context, dial DialFunc, name, port string, e entry, base *tls.Config) (net.Conn, error) {
	var last error
	for _, ip := range e.ips {
		raw, err := dial(ctx, "tcp", net.JoinHostPort(ip, port))
		if err != nil {
			last = err
			continue
		}
		cfg := base.Clone()
		if cfg.RootCAs == nil {
			cfg.RootCAs = roots()
		}
		cfg.ServerName = name
		cfg.MinVersion = tls.VersionTLS13
		cfg.EncryptedClientHelloConfigList = e.ech
		c := tls.Client(raw, cfg)
		err = c.HandshakeContext(ctx)
		// Go fails a rejected ECH handshake itself (TestServerWithoutECHIsRefused); this guards that behaviour.
		if err == nil && !c.ConnectionState().ECHAccepted {
			err = fmt.Errorf("ech not accepted by %s", name)
		}
		if err == nil {
			return c, nil
		}
		_ = raw.Close()
		var rejected *tls.ECHRejectionError
		if errors.As(err, &rejected) {
			return nil, err
		}
		last = fmt.Errorf("ech handshake with %s at %s: %w", name, ip, err)
	}
	if last == nil {
		last = errors.New("no address")
	}
	return nil, fmt.Errorf("connect %s: %w", name, last)
}

func store(host string, e entry) {
	mu.Lock()
	cache[host] = e
	mu.Unlock()
}

type result struct {
	rrs []dns.RR
	ttl uint32
	err error
}

func askAll(ctx context.Context, dial DialFunc, host string, types []uint16) []result {
	pool := dohRoots
	if pool == nil {
		pool = roots()
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext:     dial,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		// This transport lasts one lookup, so an idle connection would stay open with nothing to reuse it.
		DisableKeepAlives: true,
	}}
	results := make([]result, len(types))
	var wg sync.WaitGroup
	for i, t := range types {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rrs, ttl, err := query(ctx, client, host, t)
			results[i] = result{rrs, ttl, err}
		}()
	}
	wg.Wait()
	return results
}

// addresses gives host's A and AAAA records over DNS over HTTPS, cached by TTL under a key that cannot meet lookup's.
func addresses(ctx context.Context, dial DialFunc, host string) ([]string, error) {
	key := "doh:" + host
	mu.Lock()
	e, ok := cache[key]
	mu.Unlock()
	if ok && time.Now().Before(e.until) {
		return e.ips, nil
	}
	var v4, v6 []string
	ttl := uint32(3600)
	var last error
	for _, r := range askAll(ctx, dial, host, []uint16{dns.TypeA, dns.TypeAAAA}) {
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
	ips := append(v4, v6...)
	if len(ips) == 0 {
		if last == nil {
			last = fmt.Errorf("%s has no address in DNS", host)
		}
		return nil, last
	}
	store(key, entry{ips: ips, until: time.Now().Add(time.Duration(max(ttl, 60)) * time.Second)})
	return ips, nil
}

func lookup(ctx context.Context, dial DialFunc, host string) (entry, error) {
	mu.Lock()
	e, ok := cache[host]
	mu.Unlock()
	if ok && time.Now().Before(e.until) {
		return e, nil
	}
	results := askAll(ctx, dial, host, []uint16{dns.TypeHTTPS, dns.TypeA, dns.TypeAAAA})
	if results[0].err != nil {
		return entry{}, results[0].err
	}
	var ech []byte
	var v4, v6 []string
	ttl := results[0].ttl
	for _, rr := range results[0].rrs {
		if h, ok := rr.(*dns.HTTPS); ok {
			for _, kv := range h.Value {
				if c, ok := kv.(*dns.SVCBECHConfig); ok {
					ech = c.ECH
				}
			}
		}
	}
	for _, r := range results[1:] {
		if r.err != nil {
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
	if len(ech) == 0 {
		return entry{}, fmt.Errorf("%s publishes no ECH key; refusing a connection that would show its name", host)
	}
	ips := append(v4, v6...)
	if len(ips) == 0 {
		return entry{}, fmt.Errorf("%s has no address in DNS", host)
	}
	e = entry{ips: ips, ech: ech, until: time.Now().Add(time.Duration(max(ttl, 60)) * time.Second)}
	store(host, e)
	return e, nil
}

// query asks every resolver at once (RFC 8484, POST), because a network can block one of them and waiting it out would
// cost the client's whole timeout. It returns the first good answer's records and their smallest TTL.
func query(ctx context.Context, client *http.Client, host string, qtype uint16) ([]dns.RR, uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.Id = 0
	wire, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		rrs []dns.RR
		ttl uint32
		err error
	}
	answers := make(chan answer, len(resolvers))
	for _, url := range resolvers {
		go func() {
			rrs, ttl, err := ask(ctx, client, url, wire, host)
			answers <- answer{rrs, ttl, err}
		}()
	}
	var last error
	for range resolvers {
		a := <-answers
		if a.err == nil {
			return a.rrs, a.ttl, nil
		}
		last = a.err
	}
	return nil, 0, fmt.Errorf("dns over https for %s: %w", host, last)
}

func ask(ctx context.Context, client *http.Client, url string, wire []byte, host string) ([]dns.RR, uint32, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("doh %s: status %d %v", url, resp.StatusCode, err)
	}
	var r dns.Msg
	if err := r.Unpack(body); err != nil {
		return nil, 0, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("doh %s: %s for %s", url, dns.RcodeToString[r.Rcode], host)
	}
	ttl := uint32(3600)
	for _, rr := range r.Answer {
		ttl = min(ttl, rr.Header().Ttl)
	}
	return r.Answer, ttl, nil
}
