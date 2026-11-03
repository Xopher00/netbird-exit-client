# Shared by build-phone.sh and build-client.sh; sourced, not run. Names no deployment.

# pick LIST BUILD KIND: patch names in LIST marked BUILD; KIND is "wireguard" or "netbird".
pick() { awk -v b="$2" -v k="$3" '/^#/ || !NF {next} {w=0; n=0; for (i=2; i<=NF; i++) {if ($i=="wireguard") w=1; if ($i==b) n=1} if (n && ((k=="wireguard")==w)) print $1}' "$1" ; }

# wg_commit NB_SRC NB_VERSION: the netbirdio/wireguard-go commit that release pins.
wg_commit() {
  local c
  c=$(git -C "$1" show "$2:go.mod" | awk '$1 == "github.com/netbirdio/wireguard-go" {print $2; exit}' | sed 's/.*-//')
  [[ "$c" =~ ^[0-9a-f]{12}$ ]] || { echo "no netbirdio/wireguard-go requirement in $2 go.mod" >&2; return 1; }
  echo "$c"
}

# worktree_add SRC DIR REV: a fresh detached worktree, replacing any left over.
worktree_add() {
  worktree_drop "$1" "$2"
  git -C "$1" worktree add -q --detach "$2" "$3"
}

# worktree_drop SRC DIR
worktree_drop() {
  git -C "$1" worktree remove --force "$2" 2>/dev/null || true
  rm -rf "$2"
  git -C "$1" worktree prune
}

# maybenot_build WGWT TRIPLE TARGET_DIR LIBDIR: Maybenot's static library into WGWT/maybenot-ffi/LIBDIR/libmaybenot.a.
# The caller sets any linker variable in the environment.
maybenot_build() {
  (cd "$1/maybenot-ffi" &&
    RUSTFLAGS="-C metadata=maybenot-ffi" cargo rustc -q --crate-type=staticlib --release --locked --target "$2" --target-dir "$3")
  mkdir -p "$1/maybenot-ffi/lib/$4"
  cp "$(cd "$1/maybenot-ffi" && realpath "$3")/$2/release/libmaybenot_ffi.a" "$1/maybenot-ffi/lib/$4/libmaybenot.a"
}
