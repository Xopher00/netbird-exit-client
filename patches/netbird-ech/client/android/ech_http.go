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

// HttpResult is one answer to one of the app's own calls.
type HttpResult struct {
	Status     int
	Body       string
	RetryAfter string
}

const defaultMaxBody = 4 << 20

// Android 16's TLS has no ECH (it arrives with API 37), and the phone's DNS is what a sinkhole answers. Every call of
// the app goes through Go's client: ECH hosts get ECH, any other host a DNS over HTTPS lookup.
var httpClient = &http.Client{
	Timeout: 45 * time.Second,
	Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return ech.TLSDialer(nbnet.NewDialer().DialContext, "", &tls.Config{NextProtos: []string{"http/1.1"}})(ctx, network, addr)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 60 * time.Second,
	},
	// A token or wake key must not leave the host it was sent to.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != via[0].URL.Host || len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// HttpRequest makes one HTTPS request; headers are "Name: value" lines. A body longer than maxBody (0 for 4 MB) is an error.
func HttpRequest(method, rawURL, headers, body string, maxBody int) (*HttpResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%s is not an https address", rawURL)
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
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limit := maxBody
	if limit <= 0 {
		limit = defaultMaxBody
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("response too long")
	}
	return &HttpResult{Status: resp.StatusCode, Body: string(b), RetryAfter: resp.Header.Get("Retry-After")}, nil
}
