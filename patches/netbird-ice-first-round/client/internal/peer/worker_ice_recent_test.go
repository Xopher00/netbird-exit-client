package peer

import (
	"fmt"
	"testing"
	"time"

	"github.com/netbirdio/ice/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hostCandidate(t *testing.T, addr string) ice.Candidate {
	t.Helper()
	c, err := ice.NewCandidateHost(&ice.CandidateHostConfig{Network: "udp", Address: addr, Port: 51820, Component: 1})
	require.NoError(t, err)
	return c
}

func testOffer(session string) *OfferAnswer {
	id := ICESessionID(session)
	return &OfferAnswer{
		IceCredentials: IceCredentials{UFrag: "remoteufrag", Pwd: "remote-password-long-enough"},
		SessionID:      &id,
	}
}

// agentHas reports whether the current agent has a remote candidate at addr. It must not fail the test: it runs
// inside assert.Eventually and assert.Never, off the test goroutine.
func agentHas(w *WorkerICE, addr string) bool {
	w.muxAgent.Lock()
	agent := w.agent
	w.muxAgent.Unlock()
	if agent == nil {
		return false
	}
	cs, err := agent.GetRemoteCandidates()
	if err != nil {
		return false
	}
	for _, c := range cs {
		if c.Address() == addr {
			return true
		}
	}
	return false
}

func newRecentTestWorker(t *testing.T) *WorkerICE {
	w := newTestWorkerICE(t)
	t.Cleanup(w.Close)
	w.dialFunc = parkDial
	return w
}

// A candidate that arrives before the offer or answer that creates the agent must reach that agent, or the
// round fails and the peers stay relayed until a later round happens to get the order right.
func TestWorkerICE_CandidateBeforeAgentReachesIt(t *testing.T) {
	w := newRecentTestWorker(t)

	w.OnRemoteCandidate(hostCandidate(t, "192.0.2.10"), nil)
	w.OnNewOffer(testOffer("remote-session"))

	assert.Eventually(t, func() bool { return agentHas(w, "192.0.2.10") }, 2*time.Second, 10*time.Millisecond,
		"the kept candidate must reach the new agent")
}

// A candidate for the next session can land in the agent that the next offer replaces; the replacement must get it.
func TestWorkerICE_CandidateInReplacedAgentReachesTheNewOne(t *testing.T) {
	w := newRecentTestWorker(t)

	w.OnNewOffer(testOffer("first"))
	w.muxAgent.Lock()
	first := w.agent
	w.muxAgent.Unlock()
	w.OnRemoteCandidate(hostCandidate(t, "192.0.2.30"), nil)
	w.OnNewOffer(testOffer("second"))

	w.muxAgent.Lock()
	second := w.agent
	w.muxAgent.Unlock()
	require.NotSame(t, first, second, "the new session must replace the agent")
	assert.Eventually(t, func() bool { return agentHas(w, "192.0.2.30") }, 2*time.Second, 10*time.Millisecond,
		"the candidate must reach the replacement agent")
}

// A candidate older than the limit belongs to an abandoned negotiation and is not given to a new agent.
func TestWorkerICE_ExpiredCandidateIsNotGiven(t *testing.T) {
	w := newRecentTestWorker(t)

	w.OnRemoteCandidate(hostCandidate(t, "192.0.2.20"), nil)
	w.muxAgent.Lock()
	w.recentCandidates[0].received = time.Now().Add(-2 * recentCandidateTTL)
	w.muxAgent.Unlock()
	w.OnNewOffer(testOffer("remote-session"))

	assert.Never(t, func() bool { return agentHas(w, "192.0.2.20") }, 300*time.Millisecond, 10*time.Millisecond,
		"the expired candidate must not reach the new agent")
}

// Expired candidates leave the store when the next one arrives, so it holds only recent ones.
func TestWorkerICE_ExpiredCandidateLeavesTheStore(t *testing.T) {
	w := newRecentTestWorker(t)

	w.OnRemoteCandidate(hostCandidate(t, "192.0.2.22"), nil)
	w.muxAgent.Lock()
	w.recentCandidates[0].received = time.Now().Add(-2 * recentCandidateTTL)
	w.muxAgent.Unlock()
	w.OnRemoteCandidate(hostCandidate(t, "192.0.2.23"), nil)

	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	require.Len(t, w.recentCandidates, 1)
	assert.Equal(t, "192.0.2.23", w.recentCandidates[0].candidate.Address())
}

// The store is bounded: past the limit the oldest candidate goes.
func TestWorkerICE_RecentCandidatesAreBounded(t *testing.T) {
	w := newRecentTestWorker(t)

	for i := 0; i < maxRecentCandidates+5; i++ {
		w.OnRemoteCandidate(hostCandidate(t, fmt.Sprintf("192.0.2.%d", i+1)), nil)
	}

	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	require.Len(t, w.recentCandidates, maxRecentCandidates)
	assert.Equal(t, "192.0.2.6", w.recentCandidates[0].candidate.Address(), "the oldest five must have gone")
}

// Close ends the connection; its candidates must not reach an agent after a reopen.
func TestWorkerICE_CloseForgetsCandidates(t *testing.T) {
	w := newRecentTestWorker(t)

	w.OnRemoteCandidate(hostCandidate(t, "192.0.2.40"), nil)
	w.Close()

	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	assert.Empty(t, w.recentCandidates)
}
