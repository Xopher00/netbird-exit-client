package quic

import (
	"context"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/client/net/ech"
)

func TestQUICIsSkippedForTheECHHost(t *testing.T) {
	t.Setenv(ech.EnvHost, "vpn.example.dev")
	_, err := Dialer{}.Dial(context.Background(), "rels://vpn.example.dev:443", "vpn.example.dev")
	if err == nil || !strings.Contains(err.Error(), "requires ECH") {
		t.Fatalf("want the QUIC dial skipped, got %v", err)
	}
}
