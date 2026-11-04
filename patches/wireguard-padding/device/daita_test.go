//go:build daita

package device

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// MACHINES names a directory of <name>.txt machine files (Hopper's app/src/main/assets/padding).
func machinesFor(t *testing.T, name string) string {
	if b, err := os.ReadFile(filepath.Join("testdata", name+".txt")); err == nil {
		return strings.TrimSpace(string(b))
	}
	dir := os.Getenv("MACHINES")
	if dir == "" {
		t.Skip("MACHINES not set")
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

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
func pageLoads(t *testing.T, setup func(cli, srv *Peer)) wire {
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
	return wire{cli.txBytes.Load(), srv.txBytes.Load(), got.Load(), sent}
}

func enable(t *testing.T, p *Peer, machines string) {
	if !p.EnableDaita(machines, 1024, 1.0, 1.0) {
		t.Fatal("EnableDaita failed")
	}
	if !p.DaitaEnabled() || p.EnableDaita(machines, 1024, 1.0, 1.0) {
		t.Fatal("a second EnableDaita must be refused")
	}
}

func TestDaitaPadding(t *testing.T) {
	base := pageLoads(t, func(cli, srv *Peer) {})
	for _, family := range []string{"break_pad", "interspace"} {
		cm, sm := machinesFor(t, family+"_client"), machinesFor(t, family+"_server")
		w := pageLoads(t, func(cli, srv *Peer) { enable(t, cli, cm); enable(t, srv, sm) })
		t.Logf("%-10s client->server %7d B (base %d)  server->client %8d B (base %d)  delivered %d of %d B",
			family, w.cliTx, base.cliTx, w.srvTx, base.srvTx, w.delivered, w.sent)
		if w.delivered != w.sent {
			t.Errorf("%s: delivered %d B, want %d", family, w.delivered, w.sent)
		}
		if w.cliTx+w.srvTx <= base.cliTx+base.srvTx {
			t.Errorf("%s: no padding on the wire", family)
		}
	}
}

// A peer without DAITA drops padding as an unknown IP version and keeps every real packet.
func TestDaitaOneSided(t *testing.T) {
	sm := machinesFor(t, "interspace_server")
	w := pageLoads(t, func(cli, srv *Peer) { enable(t, srv, sm) })
	if w.delivered != w.sent {
		t.Errorf("delivered %d B, want %d", w.delivered, w.sent)
	}
}

func TestConstantPacketSize(t *testing.T) {
	base := pageLoads(t, func(cli, srv *Peer) {})
	w := pageLoads(t, func(cli, srv *Peer) { cli.SetConstantPacketSize(true); srv.SetConstantPacketSize(true) })
	t.Logf("client->server %d B (base %d)", w.cliTx, base.cliTx)
	if w.delivered != w.sent {
		t.Errorf("delivered %d B, want %d", w.delivered, w.sent)
	}
	if w.cliTx < 2*base.cliTx {
		t.Errorf("small packets were not padded: %d B against %d B", w.cliTx, base.cliTx)
	}
}

func TestDaitaStopsWithPeer(t *testing.T) {
	cm := machinesFor(t, "interspace_client")
	pair := genTestPair(t, true)
	for _, p := range pair[0].dev.peers.keyMap {
		enable(t, p, cm)
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

// A Maybenot block holds outgoing real traffic and releases it at the block's end: every packet must
// still reach the application (blocking delays, never drops), and the release counts as the packets'
// send so the machines see them. The test machine blocks 200 ms on each NormalSent, one-sided.
func TestDaitaBlocking(t *testing.T) {
	cm := machinesFor(t, "block_test_client")
	base := pageLoads(t, func(cli, srv *Peer) {})
	w := pageLoads(t, func(cli, srv *Peer) { enable(t, cli, cm) })
	if w.delivered != w.sent {
		t.Errorf("blocking lost packets: delivered %d of sent %d", w.delivered, w.sent)
	}
	if w.cliTx+w.srvTx < base.cliTx+base.srvTx {
		t.Errorf("blocked traffic lost bytes on the wire: %d against %d", w.cliTx+w.srvTx, base.cliTx+base.srvTx)
	}
}

// Peer.Stop must not hang with a block active, and held packets must not leak: their buffers return
// to the pools.
func TestDaitaStopsWithBlockActive(t *testing.T) {
	cm := machinesFor(t, "block_test_client")
	pair := genTestPair(t, true)
	for _, p := range pair[0].dev.peers.keyMap {
		enable(t, p, cm)
		pair[0].tun.Outbound <- udpPacket(pair[0].ip, pair[1].ip, 300)
		time.Sleep(50 * time.Millisecond) // the block fires and holds the packet
		if d := p.getDaita(); d == nil || !d.(*MaybenotDaita).isBlocked() {
			t.Skip("the block did not fire; the stop assert would test nothing")
		}
		done := make(chan struct{})
		go func() { p.Stop(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Peer.Stop hung with a block active")
		}
		if p.DaitaEnabled() {
			t.Fatal("DAITA still on after Stop")
		}
	}
}

// A full-size keepalive would read as data at the receiver, which answers it: the tunnel would never go quiet.
func TestConstantPacketSizeKeepsKeepalivesSmall(t *testing.T) {
	pair := genTestPair(t, true)
	for i := range pair {
		for _, p := range pair[i].dev.peers.keyMap {
			p.SetConstantPacketSize(true)
		}
	}
	pair.Send(t, Ping, nil)
	time.Sleep(KeepaliveTimeout + 3*time.Second)
	var before uint64
	for _, p := range pair[0].dev.peers.keyMap {
		before = p.txBytes.Load() + p.rxBytes.Load()
	}
	time.Sleep(2*KeepaliveTimeout + time.Second)
	for _, p := range pair[0].dev.peers.keyMap {
		if moved := p.txBytes.Load() + p.rxBytes.Load() - before; moved > 0 {
			t.Fatalf("idle tunnel moved %d B", moved)
		}
	}
}
