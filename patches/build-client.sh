#!/usr/bin/env bash
# The exit servers' NetBird client: v0.82.0 plus the WebSocket patch and the 30 s reconnect cap (stock gRPC cannot pass Cloudflare; netbird-grpc-dialer.patch) and
# Maybenot padding (off unless NB_DAITA_MACHINES or NB_DAITA_FULL_SIZE is set; Hopper's app/CLAUDE.md), and ECH to the
# host in NB_ECH_HOST, and the ICE first-round fix (netbird-ice-first-round.patch).
# Output: build/netbird-0.82.0-hopper.gz and build/SHA256SUMS, for publish.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# Two layouts: in this repo the shared patch set sits in ../../netbird-patches and the output goes to ../build/;
# in the public repo's patches/ folder everything sits beside this script and the output goes to ../build/.
if [ -f "$here/../../netbird-patches/versions.env" ]; then shared=$(cd "$here/../../netbird-patches" && pwd); pdir=$shared/patches
else shared=$here; pdir=$here; fi
source "$shared/versions.env"
source "$shared/lib.sh"
NB_SRC=${NB_SRC:-$HOME/src/netbird}
WG_SRC=${WG_SRC:-$HOME/src/wireguard-go-nb}
GO_ROOT=${GO_ROOT:-$GO_SERVER}
NAME=netbird-${NB_VERSION#v}-hopper
export GOTOOLCHAIN=local
export PATH=$GO_ROOT/bin:$PATH

build=${BUILD_DIR:-$here/../build}
mkdir -p "$build"; build=$(cd "$build" && pwd)
wt=$build/exit-client-src
wgwt=$build/wireguard-go-src

list=$shared/patches.list
nb_patches=(); wg_patches=()
while read -r patch; do nb_patches+=("$pdir/$patch"); done < <(pick "$list" exit netbird)
while read -r patch; do wg_patches+=("$pdir/$patch"); done < <(pick "$list" exit wireguard)
[ -f "$list" ] && [ "${#nb_patches[@]}" -gt 0 ] && [ "${#wg_patches[@]}" -gt 0 ] || { echo "no exit patches in $list" >&2; exit 1; }
for patch in "${nb_patches[@]}" "${wg_patches[@]}"; do
  [ -f "$patch" ] || { echo "patch not found: $patch" >&2; exit 1; }
done
git -C "$NB_SRC" rev-parse -q --verify "refs/tags/$NB_VERSION" >/dev/null || { echo "$NB_SRC has no tag $NB_VERSION" >&2; exit 1; }
# Padding goes onto the netbirdio/wireguard-go commit this NetBird release pins.
WG_COMMIT=$(wg_commit "$NB_SRC" "$NB_VERSION")
[ -d "$WG_SRC" ] || git clone -q https://github.com/netbirdio/wireguard-go.git "$WG_SRC"
git -C "$WG_SRC" rev-parse -q --verify "$WG_COMMIT^{commit}" >/dev/null || { echo "$WG_SRC has no commit $WG_COMMIT" >&2; exit 1; }

cleanup() {
  worktree_drop "$NB_SRC" "$wt"
  worktree_drop "$WG_SRC" "$wgwt"
}
cleanup
worktree_add "$NB_SRC" "$wt" "$NB_VERSION"
worktree_add "$WG_SRC" "$wgwt" "$WG_COMMIT"
trap cleanup EXIT
[ -z "$(git -C "$wt" status --porcelain)" ] || { echo "worktree is not clean" >&2; exit 1; }
git -C "$wt" apply "${nb_patches[@]}"
git -C "$wgwt" apply "${wg_patches[@]}"
git -C "$wt" diff --stat

maybenot_build "$wgwt" x86_64-unknown-linux-gnu target linux_amd64

cd "$wt"
go mod edit -replace "github.com/netbirdio/wireguard-go=$wgwt"
# A replace of a module the tree does not require is accepted silently and would build the exit without padding.
[ "$(go list -m -f '{{if .Replace}}{{.Replace.Path}}{{end}}' github.com/netbirdio/wireguard-go)" = "$wgwt" ] || { echo "$NB_VERSION does not use github.com/netbirdio/wireguard-go; update the module path" >&2; exit 1; }
rm -f "$build/$NAME"
# Static, so the sandbox's glibc does not matter; netgo and osusergo keep Go's own lookups off glibc. The linker's
# glibc warnings come from Rust's std inside libmaybenot.a, on paths Maybenot never calls.
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath -tags "daita netgo osusergo" \
  -ldflags "-s -w -linkmode external -extldflags -static -X github.com/netbirdio/netbird/version.version=${NB_VERSION#v}" \
  -o "$build/$NAME" ./client > "$build/$NAME.log" 2>&1 || { cat "$build/$NAME.log" >&2; exit 1; }
file "$build/$NAME" | grep -q "statically linked" || { echo "$NAME is not statically linked" >&2; exit 1; }

gzip -9 -n -c "$build/$NAME" > "$build/$NAME.gz"
(cd "$build" && sha256sum "$NAME") > "$build/$NAME.sha256"
# One client per NetBird version: each build replaces the file and its sums.
(cd "$build" && sha256sum "$NAME.gz" && cat "$build/$NAME.sha256") > "$build/SHA256SUMS"
ls -l "$build/$NAME.gz"
cat "$build/SHA256SUMS"
