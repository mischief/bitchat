# bitchat

A C implementation of the [BitChat](https://github.com/permissionlesstech/bitchat)
Bluetooth Low Energy mesh, with a terminal client.

Built for the mesh transport of the iOS and Android clients: the same service
UUID, the same binary packet format, signed announcements, and Noise `XX`
private sessions carrying an explicit 4-byte nonce.

Verified against a phone one way only. Announcements from real clients are
received, signature-checked and listed. Nothing sent from here has been
confirmed on a phone screen, and no private session has been run against one.

## What it does

- **Public chat** — signed broadcast messages, relayed by every node with the
  upstream flood control: TTL clamps by local degree, degree-scaled jitter,
  duplicate suppression that cancels a pending relay, and subset fanout.
- **Private chat** — end-to-end encrypted through Noise
  `XX_25519_ChaChaPoly_SHA256`.
- **Presence** — signed announcements carrying the nickname and public keys.
- **Fragments** — packets above the link size split and reassemble.
- **Receipts** — delivery and read acks for private messages, both directions.
- **Terminal UI** — ncurses, with `/who`, `/msg`, `/nick`, `/id`, `/debug` and
  `/quit`. Transport chatter stays out of the chat pane unless asked for.
  `:shortcode:` expands to emoji as you type. Tab completes commands, peer
  names and shortcodes; `@name` mentions are highlighted and ring the bell.

Not implemented: the Nostr transport, store-and-forward couriers, gossip sync,
geohash channels, media, and voice.

## Design

The radio belongs to `bluetoothd`. This registers a GATT application and an
advertisement with BlueZ and drives discovery over the system bus; it never
opens an HCI socket or takes the adapter down.

The identity lives in `~/.config/bitchat/identity` (mode 0600). The peer ID is
the first eight bytes of the SHA-256 digest of the Curve25519 public key.

## Build

```sh
meson setup build
meson compile -C build
meson test -C build
```

Needs OpenSSL 3, zlib, libsystemd (sd-bus), ncurses, and a running
`bluetoothd`.

## Run

```sh
build/src/bitchat -n grug
```

Without a radio, the same mesh runs over sockets. Two terminals:

```sh
build/src/bitchat -n grug -L 7331
build/src/bitchat -n thog -L 7332 -C 127.0.0.1:7331
```

Chain three of them and the middle node relays, which is how multi-hop is
tested here: the transport is swappable, and the mesh does not know or care
which one it is on.

## Embedding

The library holds no UI and runs on the host's event loop. Everything it
needs is a descriptor and a tick:

```c
bc_mesh_new(&mesh, &id, nick, &mesh_ops, ctx);
bc_ble_new(&ble, -1, &ble_ops, ctx);        /* never blocks on bluetoothd */

/* poll(2) loops */
n = bc_ble_pollfds(ble, fds, max);
bc_ble_dispatch(ble, fds, n);

/* loops that arm a watch once: re-arm from ops.on_events */
fd = bc_ble_fd(ble);
events = bc_ble_events(ble);

bc_ble_tick(ble);                            /* every ~200 ms */
bc_mesh_tick(mesh);
```

`contrib/weechat` is a working plugin built on exactly this. The library is
single-threaded: call it from one thread, and callbacks arrive from inside
`bc_ble_dispatch` and the tick functions.

## Text handling

Message text is UTF-8 end to end. Anything arriving that is not valid UTF-8 is
dropped, matching upstream, and control bytes are replaced before text reaches
the terminal so a peer cannot drive the emulator with escape sequences.
Payloads are deflated by upstream's rule — 100 bytes or more, under 90%
distinct bytes, and only when the result is smaller — since signatures cover
the encoded frame.

## Privacy

Announcements publish the nickname, the Curve25519 static key, the Ed25519
signing key and up to ten neighbour IDs in cleartext, and the peer ID never
rotates. Anyone in radio range can enumerate participants and follow a device
between places. Only Noise frames are padded; every other packet travels at its
natural length.
