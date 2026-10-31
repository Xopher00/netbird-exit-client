# Notices

The binary in each release is NetBird's client, built from the NetBird repository and modified by the patches in
`patches/`.

| Component | Licence | Source |
|---|---|---|
| NetBird client (everything outside `management/`, `signal/`, `relay/` and `combined/`, which the client does not include) | BSD-3-Clause, `LICENSES/netbird-LICENSE` and `LICENSES/netbird-BSD-3-Clause.txt` | https://github.com/netbirdio/netbird |
| wireguard-go, NetBird's fork, with Mullvad's DAITA padding ported by `patches/wireguard-daita.patch` | MIT, `LICENSES/wireguard-go-LICENSE` | https://github.com/netbirdio/wireguard-go, https://github.com/mullvad/wireguard-go |
| Maybenot and maybenot-ffi (traffic padding), linked statically | MIT OR Apache-2.0 (crate metadata) | https://github.com/maybenot-io/maybenot |
| Go modules compiled into the client | Each module's own licence | `MODULES.txt` lists them with versions |
