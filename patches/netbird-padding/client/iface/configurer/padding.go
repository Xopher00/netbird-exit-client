package configurer

import (
	"os"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

// "client" on the phone, "server" on the exit server, unset for no padding; set by Hopper on both ends of its tunnel.
const envPadding = "NB_DAITA"

// applyPadding is called on every peer update; a peer whose padding already runs is left alone.
func applyPadding(dev *wgbackend.Device, key wgtypes.Key) {
	role := os.Getenv(envPadding)
	if role == "" {
		return
	}
	peer := dev.LookupPeer(wgbackend.NoisePublicKey(key))
	if peer == nil || peer.DaitaEnabled() {
		return
	}
	if peer.EnablePadding(role) {
		log.Infof("padding on for peer %s", key)
	}
}

// realBytes leaves out the dummy packets, so NetBird's counts are the traffic the user's apps moved.
func realBytes(peer *wgbackend.Peer) (tx, rx int64) {
	padTx, padRx := peer.PaddingBytes()
	return int64(peer.TxBytes() - padTx), int64(peer.RxBytes() - padRx)
}
