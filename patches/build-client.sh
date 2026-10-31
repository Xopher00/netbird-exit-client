#!/usr/bin/env bash
# The exit servers' NetBird client: v0.81.5 plus the WebSocket patch (stock gRPC cannot pass Cloudflare) and
# Maybenot padding (off unless NB_DAITA_MACHINES or NB_DAITA_FULL_SIZE is set; Hopper's app/CLAUDE.md), and ECH to the
# host in NB_ECH_HOST, and the answer sent before ICE gathering starts (netbird-answer-first.patch).
# Output: build/netbird-0.81.5-hopper.gz and build/SHA256SUMS, for publish-client.sh.
set -euo pipefail

NB_VERSION=v0.81.5
NB_SRC=${NB_SRC:-$HOME/src/netbird}
WG_SRC=${WG_SRC:-$HOME/src/wireguard-go-nb}
GO_ROOT=${GO_ROOT:-$HOME/src/go1.26}
NAME=netbird-${NB_VERSION#v}-hopper
export GOTOOLCHAIN=local
export PATH=$GO_ROOT/bin:$PATH

repo=$(cd "$(dirname "$0")/.." && pwd)
# The patches live in the Android app next to this server folder.
HOPPER_APP=${HOPPER_APP:-$(cd "$repo/.." && pwd)/app}
build=$repo/build
dl=$build
wt=$build/netbird-client-src
wgwt=$build/wireguard-go-src
mkdir -p "$build" "$dl"

for patch in netbird-grpc-websocket.patch netbird-daita.patch netbird-ech.patch netbird-answer-first.patch wireguard-daita.patch; do
  [ -f "$HOPPER_APP/$patch" ] || { echo "patch not found: $HOPPER_APP/$patch" >&2; exit 1; }
done
git -C "$NB_SRC" rev-parse -q --verify "refs/tags/$NB_VERSION" >/dev/null || { echo "$NB_SRC has no tag $NB_VERSION" >&2; exit 1; }
# Padding goes onto the netbirdio/wireguard-go commit this NetBird release pins.
WG_COMMIT=$(git -C "$NB_SRC" show "$NB_VERSION:go.mod" | awk '$1 == "replace" && $2 == "golang.zx2c4.com/wireguard" {print $5}' | sed 's/.*-//')
[ -n "$WG_COMMIT" ] || { echo "no wireguard-go replace in $NB_VERSION go.mod" >&2; exit 1; }
[ -d "$WG_SRC" ] || git clone -q https://github.com/netbirdio/wireguard-go.git "$WG_SRC"
git -C "$WG_SRC" rev-parse -q --verify "$WG_COMMIT^{commit}" >/dev/null || { echo "$WG_SRC has no commit $WG_COMMIT" >&2; exit 1; }

cleanup() {
  git -C "$NB_SRC" worktree remove --force "$wt" 2>/dev/null || true
  git -C "$WG_SRC" worktree remove --force "$wgwt" 2>/dev/null || true
}
cleanup
rm -rf "$wt" "$wgwt"
git -C "$NB_SRC" worktree prune
git -C "$WG_SRC" worktree prune
git -C "$NB_SRC" worktree add --detach "$wt" "$NB_VERSION" >/dev/null
git -C "$WG_SRC" worktree add --detach "$wgwt" "$WG_COMMIT" >/dev/null
trap cleanup EXIT
[ -z "$(git -C "$wt" status --porcelain)" ] || { echo "worktree is not clean" >&2; exit 1; }
git -C "$wt" apply "$HOPPER_APP/netbird-grpc-websocket.patch" "$HOPPER_APP/netbird-daita.patch" "$HOPPER_APP/netbird-ech.patch" "$HOPPER_APP/netbird-answer-first.patch"
git -C "$wgwt" apply "$HOPPER_APP/wireguard-daita.patch"
git -C "$wt" diff --stat

(cd "$wgwt/maybenot-ffi" && RUSTFLAGS="-C metadata=maybenot-ffi" cargo rustc -q --crate-type=staticlib --release --locked --target x86_64-unknown-linux-gnu --target-dir target)
mkdir -p "$wgwt/maybenot-ffi/lib/linux_amd64"
cp "$wgwt/maybenot-ffi/target/x86_64-unknown-linux-gnu/release/libmaybenot_ffi.a" "$wgwt/maybenot-ffi/lib/linux_amd64/libmaybenot.a"

cd "$wt"
go mod edit -replace "golang.zx2c4.com/wireguard=$wgwt"
rm -f "$build/$NAME"
# Static, so the sandbox's glibc does not matter; netgo and osusergo keep Go's own lookups off glibc. The linker's
# glibc warnings come from Rust's std inside libmaybenot.a, on paths Maybenot never calls.
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath -tags "daita netgo osusergo" \
  -ldflags "-s -w -linkmode external -extldflags -static -X github.com/netbirdio/netbird/version.version=${NB_VERSION#v}" \
  -o "$build/$NAME" ./client > "$build/$NAME.log" 2>&1 || { cat "$build/$NAME.log" >&2; exit 1; }
file "$build/$NAME" | grep -q "statically linked" || { echo "$NAME is not statically linked" >&2; exit 1; }

gzip -9 -n -c "$build/$NAME" > "$dl/$NAME.gz"
(cd "$build" && sha256sum "$NAME") > "$build/$NAME.sha256"
# One client per NetBird version: each build replaces the file and its sums.
(cd "$dl" && sha256sum "$NAME.gz" && cat "$build/$NAME.sha256") > "$dl/SHA256SUMS"
ls -l "$dl/$NAME.gz"
cat "$dl/SHA256SUMS"
