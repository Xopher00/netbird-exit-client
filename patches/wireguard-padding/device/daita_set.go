//go:build daita
// +build daita

package device

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"strings"
	"sync"
)

// defenses.json is a set of generated padding-only defenses; how it was made: Hopper's reference/padding-defenses.md.
//
//go:embed defenses.json
var defensesJSON []byte

type defenseSet struct {
	ClientFrac float64 `json:"client_frac"`
	ServerFrac float64 `json:"server_frac"`
	Defenses   []struct {
		Client []string `json:"client"`
		Server []string `json:"server"`
	} `json:"defenses"`
}

var loadDefenses = sync.OnceValues(func() (defenseSet, error) {
	var s defenseSet
	err := json.Unmarshal(defensesJSON, &s)
	return s, err
})

// defenseIndex is the same at both ends of a tunnel: it hashes the two public keys in byte order. A new key, as every
// exit server has, picks another defense.
func defenseIndex(a, b NoisePublicKey, n int) int {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	sum := sha256.Sum256(append(a[:], b[:]...))
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(n))
}

// EnablePadding runs this end's half ("client" or "server") of the defense both ends pick for this peer.
func (peer *Peer) EnablePadding(role string) bool {
	set, err := loadDefenses()
	if err != nil || len(set.Defenses) == 0 {
		peer.device.log.Errorf("%v - padding: no defense set: %v", peer, err)
		return false
	}
	peer.device.staticIdentity.RLock()
	own := peer.device.staticIdentity.publicKey
	peer.device.staticIdentity.RUnlock()
	return peer.enableDefense(set, defenseIndex(own, peer.handshake.remoteStatic, len(set.Defenses)), role)
}

func (peer *Peer) enableDefense(set defenseSet, i int, role string) bool {
	machines, frac := set.Defenses[i].Client, set.ClientFrac
	if role == "server" {
		machines, frac = set.Defenses[i].Server, set.ServerFrac
	}
	if !peer.EnableDaita(strings.Join(machines, "\n"), 1024, frac, 0) {
		return false
	}
	peer.device.log.Verbosef("%v - padding: defense %d of %d, %s half", peer, i, len(set.Defenses), role)
	return true
}
