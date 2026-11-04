package grpc

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/netevents/sweep"
	"github.com/netbirdio/netbird/util/wsproxy"
)

// oneShotListener hands the connections it is given to grpc.Server.Serve.
type oneShotListener struct {
	conns chan net.Conn
	once  sync.Once
	done  chan struct{}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *oneShotListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneShotListener) Addr() net.Addr { return &net.TCPAddr{} }

// The WebSocket dialer must register its connection with the sweeper, so a
// network change cuts it at once instead of leaving it to gRPC keepalive.
func TestWebSocketConnectionIsSwept(t *testing.T) {
	testWebSocket(t, true)
}

// Without a sweeper the WebSocket dialer still connects.
func TestWebSocketWithoutSweeper(t *testing.T) {
	testWebSocket(t, false)
}

func testWebSocket(t *testing.T, withSweeper bool) {
	t.Setenv("NB_GRPC_WEBSOCKET", "true")

	lis := &oneShotListener{conns: make(chan net.Conn, 1), done: make(chan struct{})}
	srv := grpc.NewServer()
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop(); _ = lis.Close() })

	serverConn := make(chan net.Conn, 1)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c.SetReadLimit(-1)
		nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
		serverConn <- nc
		lis.conns <- nc
		<-lis.done
	}))
	t.Cleanup(hs.Close)

	sweeper := sweep.NewWithConfig(sweep.Config{SweepDelay: 10 * time.Millisecond})

	var extra []grpc.DialOption
	if withSweeper {
		extra = append(extra, WithSweeper(sweeper))
	}
	conn, err := CreateConnection(context.Background(), strings.TrimPrefix(hs.URL, "http://"), false, wsproxy.ManagementComponent, extra...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	var sc net.Conn
	select {
	case sc = <-serverConn:
	case <-time.After(5 * time.Second):
		t.Fatal("client never reached the WebSocket server")
	}

	if !withSweeper {
		return
	}
	sweeper.MarkNetworkChange()

	// A swept client socket closes; the server side then sees the WebSocket end.
	// Without the sweeper the connection stays open (keepalive needs 30 s).
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := sc.Read(buf); err != nil {
				readErr <- err
				return
			}
		}
	}()
	select {
	case <-readErr:
	case <-time.After(3 * time.Second):
		t.Fatal("WebSocket connection was not closed by the network change sweep")
	}
}
