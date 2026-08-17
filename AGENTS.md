# AGENTS.md

A C client for the BitChat BLE mesh. See [README.md](README.md) for what it
does and how to build it.

## Layout

| Path | Contents |
|---|---|
| `bitchat/` | Installed public headers |
| `lib/` | The library: packet, tlv, crypto, noise, mesh, ble, util |
| `src/` | The `bitchat` binary: ncurses UI and the poll loop |
| `test/` | Unit tests plus a two-node mesh test with a fake link |
| `libemoji/` | `:shortcode:` table vendored from clm, lua at build time only |
| `contrib/weechat/` | WeeChat plugin, built when the plugin header is present |
| `man/` | mdoc man page |

## Rules

- BSD KNF, tabs, 80 columns. `.clang-format` is authoritative.
- Public symbols are `bc_*` and listed in `lib/libbitchat.map`.
- Errors return negative errno. `ASSERT_RETURN` guards public entry points;
  `assert` is for internal invariants.
- Include `banned.h` last. It poisons `strcpy`, `sprintf`, `atoi` and friends.
- Do not add stack buffers over ~1 KiB: the build fails at 2 KiB frames.

## Protocol

The wire format follows the upstream Swift implementation. Interop-critical
details:

- Signatures cover the packet encoded with TTL 0, no signature, no RSR flag,
  and padding applied.
- The peer ID is the first 8 bytes of `SHA-256(noise_pub)`; announcements that
  disagree are dropped.
- Only `noiseEncrypted` and `noiseHandshake` frames are padded, PKCS#7-style,
  toward 256/512/1024/2048 bytes.
- Compressed payloads use raw deflate, with the original size in front.
- Fragment payloads are `id[8] index[2] total[2] type[1]` then the chunk.
  Sets are capped at 256 on send, since deployed clients reject more, and up
  to 512 are accepted on receive.
- Fragments are cut to the smallest link the node holds, and a link that has
  not reported an MTU counts as the floor. Sizing is global rather than
  per-link, so one small link shrinks every fragment; per-link sizing would
  mean fragmenting inside the send path instead of above it.
- Transport frames inside a session are `nonce[4] big endian || ciphertext ||
  tag[16]`. The nonce is on the wire, and the receiver keeps a 1024-entry
  sliding replay window rather than a counter.
- Compression follows upstream exactly: deflate a payload of 100 bytes or more
  whose distinct byte count over a 256-byte yardstick is under 90%, and keep
  the result only when it is smaller. Signatures cover the encoded frame, so a
  disagreement here shows up as a rejected signature on the peer.

## Text

All strings from the mesh are untrusted. `bc_utf8_valid` gates them before
they reach a buffer or a terminal, `bc_utf8_truncate` keeps truncation on a
character boundary, and the UI replaces control bytes so escape sequences from
a peer cannot repaint the screen.

## Relaying

Flood control mirrors upstream's `RelayController` and `BLEFanoutSelector`:

- Sync requests never relay. TTL is capped at 7 on ingress, and a packet
  addressed to us is delivered, not forwarded.
- Handshakes and directed encrypted or fragment traffic relay at TTL - 1 with
  tight jitter (10-35 ms, 20-60 ms): losing those costs a conversation.
- Fragments and voice clamp to TTL 5 when the node has 6 or more links, 7
  otherwise, with 8-25 ms jitter.
- Other broadcasts clamp to 5 when dense, keep full depth at 2 links or fewer,
  and otherwise cap at 7 for announces and 6 for the rest. Jitter widens with
  degree, up to 100-220 ms, so duplicate suppression wins the race.
- Broadcasts other than announces, fragments and sync go to a subset of links
  (~log2 of the degree, chosen by digest of the packet key and the link), the
  ingress link always excluded.

## Transports

`bc_ble` (bluetoothd) and `bc_tcp` (sockets) present the same shape: pollfds,
dispatch, timeout, tick, send, broadcast. The mesh only knows opaque link
tokens, so tests and multi-node runs use the socket transport. `test_net`
drives three meshes over loopback; `test_relay` does the same in-process.

Virtual Bluetooth controllers need `CONFIG_BT_HCIVHCI` and root: HCI over a
socket (btproxy and friends) feeds a userspace stack, and ours is the kernel's.
Test the mesh over `bc_tcp` instead, and the radio against real hardware.

## Radio

BlueZ owns the adapter. Every call into BlueZ is async: registration
deadlocks otherwise, since BlueZ calls back into our exported objects while it
handles it, and an embedder's event loop must never stall on the daemon.

The transport runs on one descriptor. Its wanted events change as the bus
queues writes, hence `ops.on_events`; a host that arms a watch once must
re-arm outside the fd callback, not inside it.

## Build and test

```sh
meson setup build && meson compile -C build && meson test -C build
ninja -C build clang-format-check
ninja -C build cppcheck
```

Sanitizers, which the release flags deliberately turn off:

```sh
meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false \
    -Ddefault_library=static -Dc_link_args=-static-libasan
meson test -C build-asan
```

Static linking and `-static-libasan` are not optional here: a shared build
aborts with "ASan runtime does not come first". `-fsanitize-trap=all` is
dropped automatically when a sanitizer is on, since a trap raises SIGILL with
no message and hides the finding it was meant to expose.

Radio behaviour is not covered by the test suite. Test it against a phone
running BitChat.

Both ends of the handshake tests are this implementation, so a symmetric
deviation from the specification would pass. `test_initial_hash` pins the
transcript to a value computed outside the code; extend that approach rather
than trusting a green suite for interoperation.
