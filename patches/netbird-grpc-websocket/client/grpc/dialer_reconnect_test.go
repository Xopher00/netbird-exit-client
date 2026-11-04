package grpc

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestReconnectWaitIsCappedWithJitter(t *testing.T) {
	if got := reconnectParams.Backoff.MaxDelay; got != 30*time.Second {
		t.Fatalf("reconnect cap = %v, want 30s", got)
	}
	if reconnectParams.Backoff.Jitter <= 0 {
		t.Fatal("reconnect wait lost its jitter: clients would retry in step")
	}
}

// A dial through a WebSocket with a DNS-over-HTTPS lookup can take longer than the first backoff of 1 s.
func TestDialKeepsItsTimeWithTheShortFirstBackoff(t *testing.T) {
	var mu sync.Mutex
	var left time.Duration
	dialer := grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		if d, ok := ctx.Deadline(); ok {
			mu.Lock()
			left = time.Until(d)
			mu.Unlock()
		}
		return nil, errors.New("refused")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if conn, err := CreateConnection(ctx, "passthrough:///test", false, "/test", dialer); err == nil {
		conn.Close()
		t.Fatal("dial should not succeed")
	}

	mu.Lock()
	defer mu.Unlock()
	if left < 15*time.Second {
		t.Fatalf("first dial got %v, want gRPC's 20 s", left)
	}
}
