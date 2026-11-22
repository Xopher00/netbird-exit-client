package dns

import (
	"context"

	"github.com/miekg/dns"

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/net/doh"
)

// dohChain answers the cache of NetBird's own server names over DNS over HTTPS, on NetBird's own sockets. Through the
// handler chain or the system resolver the control server's name went in plain DNS to the network or the nameservers.
type dohChain struct{}

func (dohChain) ResolveInternal(ctx context.Context, msg *dns.Msg, _ int) (*dns.Msg, error) {
	return doh.Resolve(ctx, nbnet.NewDialer().DialContext, msg)
}

func (dohChain) HasRootHandlerAtOrBelow(int) bool { return true }
