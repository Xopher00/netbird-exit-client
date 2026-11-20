//go:build daita

package device

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// The phone link the first attempt was slow on: an 8 Mbit/s uplink, 40 down, 20 ms each way.
var phoneUp, phoneDown = link{8e6, 20 * time.Millisecond, 100}, link{40e6, 20 * time.Millisecond, 100}

type latency struct {
	lightP95, loadedP50, loadedP95 time.Duration
	mbits                          float64
	padTx, padRx                   [2]uint64
}

// echo sends 100 bytes every 100 ms until stop closes and returns the sorted round trips.
func echo(c net.Conn, stop <-chan struct{}) []time.Duration {
	var rtts []time.Duration
	buf := make([]byte, 100)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			sort.Slice(rtts, func(a, b int) bool { return rtts[a] < rtts[b] })
			return rtts
		case <-tick.C:
		}
		start := time.Now()
		_ = c.SetDeadline(start.Add(5 * time.Second))
		if _, err := c.Write(buf); err == nil {
			_, err = io.ReadFull(c, buf)
		}
		rtts = append(rtts, time.Since(start)) // a failed echo counts at its full wait
	}
}

func pctl(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return time.Hour
	}
	return d[int(p*float64(len(d)-1))]
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// measure: an echo alone for 5 s, then during a 12 MB download from the server.
func measure(t *testing.T, enable func(cli, srv *Peer)) latency {
	p := newTCPPair(t, phoneUp, phoneDown)
	enable(p.peer(0), p.peer(1))
	srv := p.ip[1]
	const size = 12 << 20
	listen := func(port uint16, serve func(net.Conn)) {
		l, err := p.nets[1].ListenTCPAddrPort(netip.AddrPortFrom(srv, port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			if c, err := l.Accept(); err == nil {
				serve(c)
			}
		}()
	}
	listen(7, func(c net.Conn) { _, _ = io.Copy(c, c) })
	listen(9, func(c net.Conn) { _, _ = io.CopyN(c, zeroReader{}, size); c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ec, err := p.nets[0].DialContextTCPAddrPort(ctx, netip.AddrPortFrom(srv, 7))
	if err != nil {
		t.Fatal(err)
	}
	defer ec.Close()
	stop := make(chan struct{})
	time.AfterFunc(5*time.Second, func() { close(stop) })
	light := echo(ec, stop)

	stop = make(chan struct{})
	loaded := make(chan []time.Duration)
	go func() { loaded <- echo(ec, stop) }()
	start := time.Now()
	bc, err := p.nets[0].DialContextTCPAddrPort(ctx, netip.AddrPortFrom(srv, 9))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, bc)
	took := time.Since(start)
	close(stop)
	l := <-loaded
	if n != size {
		t.Errorf("downloaded %d of %d bytes", n, size)
	}
	r := latency{lightP95: pctl(light, 0.95), loadedP50: pctl(l, 0.5), loadedP95: pctl(l, 0.95), mbits: float64(n*8) / took.Seconds() / 1e6}
	for i := range 2 {
		r.padTx[i], r.padRx[i] = p.peer(i).PaddingBytes()
	}
	return r
}

// TestDaitaSelect, with DAITA_SELECT=<file>, writes each defense whose speed is two thirds of padding off's or more.
// Middle of three runs: one run varies by a third even with padding off (notes/padding-delay.md).
func TestDaitaSelect(t *testing.T) {
	out := os.Getenv("DAITA_SELECT")
	if out == "" {
		t.Skip("DAITA_SELECT not set")
	}
	set, err := loadDefenses()
	if err != nil {
		t.Fatal(err)
	}
	middle := func(enable func(cli, srv *Peer)) float64 {
		var m [3]float64
		for k := range m {
			m[k] = measure(t, enable).mbits
		}
		sort.Float64s(m[:])
		return m[1]
	}
	var kept []string
	var off float64
	for i := range set.Defenses {
		if i%10 == 0 {
			off = middle(func(cli, srv *Peer) {})
		}
		mbits := middle(func(cli, srv *Peer) { cli.enableDefense(set, i, "client"); srv.enableDefense(set, i, "server") })
		ok := mbits >= off*2/3
		t.Logf("defense %3d: %5.1f Mbit/s, off %5.1f, kept %t", i, mbits, off, ok)
		if ok {
			kept = append(kept, fmt.Sprint(i))
		}
	}
	if err := os.WriteFile(out, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDaitaLatency holds padding to the bar the first attempt failed: on a phone-like link, use with padding feels
// like use without it, also during a download. Ten defenses spread across the set; about 2 minutes.
func TestDaitaLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("about 2 minutes")
	}
	set, err := loadDefenses()
	if err != nil {
		t.Fatal(err)
	}
	off := measure(t, func(cli, srv *Peer) {})
	t.Logf("off:         light p95 %4dms  loaded p50 %4dms p95 %4dms  %5.1f Mbit/s", off.lightP95.Milliseconds(),
		off.loadedP50.Milliseconds(), off.loadedP95.Milliseconds(), off.mbits)
	for k := range 10 {
		i := k * len(set.Defenses) / 10
		r := measure(t, func(cli, srv *Peer) {
			if !cli.enableDefense(set, i, "client") || !srv.enableDefense(set, i, "server") {
				t.Fatalf("defense %d: enabling failed", i)
			}
		})
		t.Logf("defense %3d: light p95 %4dms  loaded p50 %4dms p95 %4dms  %5.1f Mbit/s  dummy bytes up %d down %d", i,
			r.lightP95.Milliseconds(), r.loadedP50.Milliseconds(), r.loadedP95.Milliseconds(), r.mbits, r.padTx[0], r.padTx[1])
		if d := r.lightP95 - off.lightP95; d > 5*time.Millisecond {
			t.Errorf("defense %d: light use 95th percentile %v above padding off", i, d)
		}
		if d := r.loadedP50 - off.loadedP50; d > 15*time.Millisecond {
			t.Errorf("defense %d: median during the download %v above padding off", i, d)
		}
		if d := r.loadedP95 - off.loadedP95; d > 40*time.Millisecond {
			t.Errorf("defense %d: 95th percentile during the download %v above padding off", i, d)
		}
	}
}
