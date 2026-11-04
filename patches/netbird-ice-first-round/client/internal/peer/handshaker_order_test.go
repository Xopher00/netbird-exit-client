package peer

import (
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The offerer drops candidates that arrive before the answer, so the answer must be sent before the ICE
// listener starts gathering and signaling candidates.
func TestHandshakerSendsAnswerBeforeICEListener(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}

	key, err := wgtypes.GeneratePrivateKey()
	assert.NoError(t, err)
	client := &signal.MockClient{SendFunc: func(msg *sProto.Message) error {
		if msg.GetBody().GetType() == sProto.Body_ANSWER {
			record("answer")
		}
		return nil
	}}
	relay := &WorkerRelay{relayManager: relayClient.NewManager(t.Context(), nil, "test", 1280)}
	h := NewHandshaker(log.WithField("test", t.Name()), ConnConfig{Key: "remote"}, NewSignaler(client, key), nil, relay, nil)

	done := make(chan struct{})
	h.AddICEListener(func(*OfferAnswer) {
		record("ice")
		close(done)
	})
	go h.Listen(t.Context())

	h.OnRemoteOffer(OfferAnswer{IceCredentials: IceCredentials{UFrag: "ufrag", Pwd: "pwd"}})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ICE listener was not called")
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"answer", "ice"}, events)
}
