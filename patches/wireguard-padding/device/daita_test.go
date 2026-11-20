//go:build daita

package device

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func udpPacket(src, dst netip.Addr, payload int) []byte {
	p := make([]byte, 20+8+payload)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8], p[9] = 64, 17
	s, d := src.As4(), dst.As4()
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	return p
}

type wire struct{ cliTx, srvTx, delivered, sent uint64 }

// Three page loads: a small request, a burst of full-size packets back, then idle.
func pageLoads(t *testing.T, setup func(cli, srv *Peer)) (wire, *Peer, *Peer) {
	pair := genTestPair(t, true)
	peerOf := func(i int) *Peer {
		for _, p := range pair[i].dev.peers.keyMap {
			return p
		}
		return nil
	}
	cli, srv := peerOf(0), peerOf(1)
	setup(cli, srv)

	var got atomic.Uint64
	stop := make(chan struct{})
	defer close(stop)
	for i := range pair {
		go func(i int) {
			for {
				select {
				case b := <-pair[i].tun.Inbound:
					got.Add(uint64(len(b)))
				case <-stop:
					return
				}
			}
		}(i)
	}
	var sent uint64
	c, s := pair[0].ip, pair[1].ip
	for range 3 {
		p := udpPacket(c, s, 300)
		sent += uint64(len(p))
		pair[0].tun.Outbound <- p
		time.Sleep(50 * time.Millisecond)
		for range 60 {
			p := udpPacket(s, c, 1200)
			sent += uint64(len(p))
			pair[1].tun.Outbound <- p
			time.Sleep(2 * time.Millisecond)
		}
		time.Sleep(time.Second)
	}
	time.Sleep(2 * time.Second)
	return wire{cli.txBytes.Load(), srv.txBytes.Load(), got.Load(), sent}, cli, srv
}

func enable(t *testing.T, p *Peer, role string) {
	if !p.EnablePadding(role) {
		t.Fatal("EnablePadding failed")
	}
	if !p.DaitaEnabled() || p.EnablePadding(role) {
		t.Fatal("a second EnablePadding must be refused")
	}
}

func TestDaitaPadding(t *testing.T) {
	base, _, _ := pageLoads(t, func(cli, srv *Peer) {})
	w, cli, srv := pageLoads(t, func(cli, srv *Peer) { enable(t, cli, "client"); enable(t, srv, "server") })
	t.Logf("client->server %7d B (base %d)  server->client %8d B (base %d)  delivered %d of %d B",
		w.cliTx, base.cliTx, w.srvTx, base.srvTx, w.delivered, w.sent)
	if w.delivered != w.sent {
		t.Errorf("delivered %d B, want %d", w.delivered, w.sent)
	}
	if w.cliTx+w.srvTx <= base.cliTx+base.srvTx {
		t.Error("no padding on the wire")
	}
	// What one end counts as dummies sent, the other counts as dummies received, give or take packets in flight.
	cli.Stop()
	srv.Stop()
	cliTx, cliRx := cli.PaddingBytes()
	srvTx, srvRx := srv.PaddingBytes()
	if cliTx+srvTx == 0 {
		t.Error("no dummy bytes counted")
	}
	for _, d := range []struct{ sent, got uint64 }{{cliTx, srvRx}, {srvTx, cliRx}} {
		if diff := int64(d.sent) - int64(d.got); diff < 0 || diff > 4*1500 {
			t.Errorf("dummy bytes sent %d, received %d", d.sent, d.got)
		}
	}
}

// The idle turn-off reads bytes minus dummy bytes; that must be the same traffic as with padding off.
func TestDaitaRealBytes(t *testing.T) {
	stopped := func(p *Peer) (tx, padTx uint64) {
		p.Stop()
		padTx, _ = p.PaddingBytes()
		return p.txBytes.Load(), padTx
	}
	_, offCli, offSrv := pageLoads(t, func(cli, srv *Peer) {})
	offCliTx, _ := stopped(offCli)
	offSrvTx, _ := stopped(offSrv)
	_, cli, srv := pageLoads(t, func(cli, srv *Peer) { enable(t, cli, "client"); enable(t, srv, "server") })
	cliTx, cliPad := stopped(cli)
	srvTx, srvPad := stopped(srv)
	for _, c := range []struct {
		name            string
		wire, pad, base uint64
	}{{"client", cliTx, cliPad, offCliTx}, {"server", srvTx, srvPad, offSrvTx}} {
		real, slack := int64(c.wire-c.pad), max(int64(c.base)/50, 256) // 2%, or a few keepalives on the small side
		if d := real - int64(c.base); d < -slack || d > slack {
			t.Errorf("%s: real bytes %d with padding, %d without (dummy bytes %d)", c.name, real, c.base, c.pad)
		}
	}
}

// A peer without DAITA drops padding as an unknown IP version and keeps every real packet.
func TestDaitaOneSided(t *testing.T) {
	w, _, _ := pageLoads(t, func(cli, srv *Peer) { enable(t, srv, "server") })
	if w.delivered != w.sent {
		t.Errorf("delivered %d B, want %d", w.delivered, w.sent)
	}
}

func TestDaitaStopsWithPeer(t *testing.T) {
	pair := genTestPair(t, true)
	for _, p := range pair[0].dev.peers.keyMap {
		enable(t, p, "client")
		done := make(chan struct{})
		go func() { p.Stop(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Peer.Stop hung with DAITA on")
		}
		if p.DaitaEnabled() {
			t.Fatal("DAITA still on after Stop")
		}
	}
}

func TestDefenseIndex(t *testing.T) {
	var a, b, c NoisePublicKey
	a[0], b[0], c[0] = 1, 2, 3
	if defenseIndex(a, b, 500) != defenseIndex(b, a, 500) {
		t.Error("the two ends of one tunnel pick different defenses")
	}
	picks := map[int]bool{}
	for i := range 50 {
		c[1] = byte(i)
		picks[defenseIndex(a, c, 500)] = true
	}
	if len(picks) < 40 {
		t.Errorf("50 keys picked only %d defenses", len(picks))
	}
}

func TestDummySize(t *testing.T) {
	var d MaybenotDaita
	if got := d.dummySize(1280); got != int(DaitaHeaderLen) {
		t.Errorf("before any real packet: %d, want %d", got, DaitaHeaderLen)
	}
	d.RecordSize(52)
	d.RecordSize(1280)
	for range 100 {
		if got := d.dummySize(1280); got != 52 && got != 1280 {
			t.Fatalf("dummy size %d is no size the peer sent", got)
		}
	}
	d.RecordSize(9000)
	for range 100 {
		if got := d.dummySize(1280); got > 1280 {
			t.Fatalf("dummy size %d is over the MTU", got)
		}
	}
}
