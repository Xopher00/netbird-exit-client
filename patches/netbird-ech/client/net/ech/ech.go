// Package ech dials TLS with Encrypted Client Hello whenever the name publishes a key, looked up over DNS over HTTPS.
// Hopper's own hosts (NB_ECH_HOST, comma-separated) must publish one.
package ech

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/netbirdio/netbird/client/net/doh"
)

const EnvHost = "NB_ECH_HOST"

// lookup is doh.Lookup; a variable for tests.
var lookup = doh.Lookup

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

// TLSDialer returns a DialTLSContext for an http.Transport. name, when set, is the TLS server name the caller expects
// regardless of the address dialled.
func TLSDialer(dial doh.DialFunc, name string, base *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		server := cmp.Or(name, host)
		return DialTLS(ctx, dial, addr, server, base, On(server) || On(host))
	}
}

// DialTLS connects to addr with TLS for name, at an address from DNS over HTTPS unless addr already holds one, and with
// ECH when name publishes a key. required refuses a name without a key, so it is never sent in clear.
func DialTLS(ctx context.Context, dial doh.DialFunc, addr, name string, base *tls.Config, required bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	name = cmp.Or(name, host)
	// An address as the name has nothing to look up, and TLS sends no name for it.
	var e doh.Entry
	if net.ParseIP(name) == nil {
		if e, err = keyed(ctx, dial, name, required); err != nil {
			return nil, err
		}
	}
	// A literal address is for this dial only: the cache keeps the name's DNS addresses, and a key that front sends
	// back is not cached for the name either, since it may not be the front DNS names.
	literal := net.ParseIP(host) != nil
	if literal {
		e.IPs = []string{host}
	}
	conn, err := handshake(ctx, dial, name, port, e, base)
	// A server whose key changed answers with the new one; one retry with it.
	var rejected *tls.ECHRejectionError
	if errors.As(err, &rejected) && len(rejected.RetryConfigList) > 0 {
		e.ECH = rejected.RetryConfigList
		if !literal {
			doh.SetKey(name, e.ECH)
		}
		conn, err = handshake(ctx, dial, name, port, e, base)
	}
	return conn, err
}

// keyed looks name up; for a required name, a missing key or a failed key lookup refuses before any connection.
func keyed(ctx context.Context, dial doh.DialFunc, name string, required bool) (doh.Entry, error) {
	e, err := lookup(ctx, dial, name)
	switch {
	case err != nil:
		return doh.Entry{}, err
	case required && e.KeyErr != nil:
		return doh.Entry{}, e.KeyErr
	case required && len(e.ECH) == 0:
		return doh.Entry{}, fmt.Errorf("%s publishes no ECH key; refusing a connection that would show its name", name)
	}
	return e, nil
}

func handshake(ctx context.Context, dial doh.DialFunc, name, port string, e doh.Entry, base *tls.Config) (net.Conn, error) {
	var last error
	for _, ip := range e.IPs {
		raw, err := dial(ctx, "tcp", net.JoinHostPort(ip, port))
		if err != nil {
			last = err
			continue
		}
		c := tls.Client(raw, tlsConfig(base, name, e.ECH))
		if err = c.HandshakeContext(ctx); err == nil {
			// Go fails a rejected ECH handshake itself; this guards that behaviour.
			if len(e.ECH) == 0 || c.ConnectionState().ECHAccepted {
				return c, nil
			}
			err = fmt.Errorf("ech not accepted by %s", name)
		}
		_ = raw.Close()
		var rejected *tls.ECHRejectionError
		if errors.As(err, &rejected) {
			return nil, err
		}
		last = fmt.Errorf("tls handshake with %s at %s: %w", name, ip, err)
	}
	if last == nil {
		last = errors.New("no address")
	}
	return nil, fmt.Errorf("connect %s: %w", name, last)
}

// tlsConfig is base for name, with ECH, which needs TLS 1.3, when a key is given.
func tlsConfig(base *tls.Config, name string, ech []byte) *tls.Config {
	cfg := base.Clone()
	cfg.RootCAs = cmp.Or(cfg.RootCAs, doh.Roots())
	cfg.ServerName = name
	if len(ech) > 0 {
		cfg.MinVersion, cfg.EncryptedClientHelloConfigList = tls.VersionTLS13, ech
	}
	return cfg
}
