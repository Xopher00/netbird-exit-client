//go:build daita

package device

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netbirdio/wireguard-go/conn"
	"github.com/netbirdio/wireguard-go/tun/netstack"
)

// link is one direction of an emulated path: a rate limit, a bounded queue (more is dropped), then a fixed delay.
type link struct {
	bitsPerSec float64
	delay      time.Duration
	queue      int
}

type linkPacket struct {
	b  []byte
	ep conn.Endpoint
	at time.Time
}

type linkBind struct {
	conn.Bind
	q       chan linkPacket
	dropped atomic.Uint64
}

func newLinkBind(tb testing.TB, inner conn.Bind, l link) *linkBind {
	s := &linkBind{Bind: inner, q: make(chan linkPacket, l.queue)}
	done := make(chan struct{})
	tb.Cleanup(func() { close(done) })
	delayed := make(chan linkPacket, 1<<16)
	go func() {
		for {
			select {
			case p := <-delayed:
				time.Sleep(time.Until(p.at))
				_ = s.Bind.Send([][]byte{p.b}, p.ep)
			case <-done:
				return
			}
		}
	}()
	go func() {
		var free time.Time
		for {
			select {
			case p := <-s.q:
				// A sleep overshoots by up to a millisecond; free may lag by 3 ms so the average rate still holds.
				if floor := time.Now().Add(-3 * time.Millisecond); free.Before(floor) {
					free = floor
				}
				free = free.Add(time.Duration(float64(len(p.b)*8) / l.bitsPerSec * float64(time.Second)))
				time.Sleep(time.Until(free))
				p.at = time.Now().Add(l.delay)
				delayed <- p
			case <-done:
				return
			}
		}
	}()
	return s
}

func (s *linkBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, b := range bufs {
		select {
		case s.q <- linkPacket{b: append([]byte(nil), b...), ep: ep}:
		default:
			s.dropped.Add(1)
		}
	}
	return nil
}

// tcpPair is two peers on wireguard-go's userspace TCP stack, joined by an emulated link in each direction.
type tcpPair struct {
	dev  [2]*Device
	nets [2]*netstack.Net
	ip   [2]netip.Addr
}

func newTCPPair(tb testing.TB, up, down link) *tcpPair {
	p := &tcpPair{}
	cfg, endpointCfg := genConfigs(tb)
	for i, l := range []link{up, down} {
		p.ip[i] = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		tun, n, err := netstack.CreateNetTUN([]netip.Addr{p.ip[i]}, nil, 1280)
		if err != nil {
			tb.Fatal(err)
		}
		p.nets[i] = n
		p.dev[i] = NewDevice(tun, newLinkBind(tb, conn.NewDefaultBind(), l), NewLogger(LogLevelError, fmt.Sprintf("dev%d: ", i)))
		if err := p.dev[i].IpcSet(cfg[i]); err != nil {
			tb.Fatal(err)
		}
		if err := p.dev[i].Up(); err != nil {
			tb.Fatal(err)
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], p.dev[i].net.port)
	}
	for i := range p.dev {
		if err := p.dev[i].IpcSet(endpointCfg[i]); err != nil {
			tb.Fatal(err)
		}
		tb.Cleanup(p.dev[i].Close)
	}
	return p
}

func (p *tcpPair) peer(i int) *Peer {
	for _, peer := range p.dev[i].peers.keyMap {
		return peer
	}
	return nil
}
