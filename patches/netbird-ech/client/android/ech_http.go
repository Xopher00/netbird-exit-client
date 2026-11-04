package android

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/net/ech"
)

// EchResult is one answer to the app's own call to its server.
type EchResult struct {
	Status     int
	Body       string
	RetryAfter string
}

// Android 16's TLS has no ECH (it arrives with API 37), so the app's calls to its own server go through Go's.
var echClient = &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{
	DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return ech.DialTLS(ctx, nbnet.NewDialer().DialContext, addr, "", &tls.Config{NextProtos: []string{"http/1.1"}})
	},
	MaxIdleConns:    2,
	IdleConnTimeout: 60 * time.Second,
}}

// EchRequest makes one HTTPS request to the ECH host; headers are "Name: value" lines.
func EchRequest(method, rawURL, headers, body string) (*EchResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || !ech.On(u.Hostname()) {
		return nil, fmt.Errorf("%s is not the ECH host", u.Hostname())
	}
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, r)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(headers, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	resp, err := echClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return &EchResult{Status: resp.StatusCode, Body: string(b), RetryAfter: resp.Header.Get("Retry-After")}, nil
}
