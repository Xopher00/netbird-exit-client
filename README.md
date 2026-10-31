# netbird-exit-client

A Linux (amd64) build of the [NetBird](https://github.com/netbirdio/netbird) client for short-lived exit servers.
It is NetBird v0.81.5 with five patches, in `patches/`:

- `netbird-grpc-websocket.patch`: with `NB_GRPC_WEBSOCKET=true`, gRPC to the management and signal servers runs
  inside the server's WebSocket wrapper, for servers behind proxies that do not pass gRPC.
- `netbird-daita.patch` and `wireguard-daita.patch`: optional traffic padding (Maybenot, as in Mullvad's DAITA),
  off unless `NB_DAITA_MACHINES` or `NB_DAITA_FULL_SIZE` is set.
- `netbird-ech.patch`: connections to the host named in `NB_ECH_HOST` look it up over DNS over HTTPS and use
  Encrypted Client Hello, or are refused.
- `netbird-answer-first.patch`: a peer answering an offer sends the answer before its ICE agent starts sending
  candidates, which the offering peer would otherwise drop, so direct connections form at once
  ([netbirdio/netbird#8443](https://github.com/netbirdio/netbird/discussions/8443)).

## Download

Each release holds one file, `netbird-0.81.5-hopper.gz` (gzip). The release tag is the NetBird version and the first
8 characters of the file's SHA-256. Check the whole checksum, listed in the release notes, before running it.

## Build

`patches/build-client.sh` is the script that builds the release file: a static cgo build (`-tags "daita netgo
osusergo"`) of `./client` with the patches applied to NetBird v0.81.5 and to the wireguard-go commit it pins.

## Licence

See `NOTICE.md`.
