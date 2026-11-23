# Security Policy

Another Dimension v2 is a local, serverless 1:1 text chat for Apple Silicon macOS. It is a personal learning and portfolio project. **It has not had an independent security audit, and the cryptography here must not be treated as a security guarantee.** This document states what the project tries to protect, what it does not, and which weaknesses are already known.

한국어 요약: 이 문서는 앱이 보호하려는 것, 보호하지 않는 것, 이미 알려진 한계를 정리합니다. 독립 감사는 받지 않았습니다. 자세한 구조는 [docs/architecture.md](docs/architecture.md), 설계 결정은 [docs/adr/](docs/adr/), 수정 이력은 [docs/security-fixes.md](docs/security-fixes.md)를 보세요.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") on the repository. Include the commit, the steps to reproduce, and the impact you observed. This is a one-person project, so there is no response-time guarantee; I will acknowledge reports as soon as I can.

## Assets

| Asset | Why it matters |
|---|---|
| Identity seed (the personal access code) | Anyone holding it can restore and impersonate the identity. |
| Conversation history | Message text, timestamps and signatures, stored encrypted on disk. |
| Verified-contact records | Which peers the user has confirmed, and the secrets used to reconnect to them. |
| Backup files | Encrypted exports that the user moves between devices. |

## Attacker model

| Attacker | Capability assumed | Intended outcome |
|---|---|---|
| Web page in the user's browser | Can send requests to `127.0.0.1` | Cannot call the local API (Host/Origin checks, bearer token, strict CSP). |
| Relay operator or network observer | Sees and tampers with relay traffic | Cannot read or forge messages; can see metadata (see below). |
| Other relay subscribers | Can subscribe to the public event kind | Cannot read content; can see event sizes and timing. |
| Person who obtains a backup file | Has the file, not the access code | Cannot read it (ADBACK7 / ADPACK3 need the identity key, and optionally a password). |
| Person who obtains the data directory | Has the files, not the access code | Cannot read history or contact records. |
| Another local process of the same user | Can read process memory and the user's files | **Out of scope.** An endpoint compromise defeats the application. |

## What the application tries to guarantee

- Messages are protected in transit by a Noise XX session. Each side signs the handshake hash with its Ed25519 identity key inside the encrypted channel, so the relay cannot see or swap identities.
- Chat frames are accepted only after both users have compared a short code through a separate channel and confirmed it. The code is derived from the handshake, both identities and a random value from each side. Each side commits to its value inside its signed identity proof and reveals it only after receiving the other's commitment, so a man in the middle cannot choose values that make the codes on his two connections match; he can only guess. The code has twelve decimal digits (about 40 bits). The protocol version is 3, and a peer on version 2 cannot connect.
- New messages carry an Ed25519 signature over their id, time and text, which is verified when history is restored from a peer.
- History, contact records and current-format backups are authenticated and encrypted. A modified file is rejected instead of being silently accepted.
- Each kind of stored file (history index, linked-key store, contact record, contact backup, backup) is encrypted with a key of its own, derived from the identity under a separate label; conversation log records still use the storage key directly. Release builds keep data in the user's Application Support folder, and a data directory chosen through `ANOTHER_DIMENSION_DATA_DIR` is accepted only if it is safe to keep secrets in.
- In Tor mode, every relay connection goes through the configured SOCKS proxy with remote name resolution, and the application never falls back to a direct connection. Each connection presents random SOCKS5 credentials of its own (RFC 1929), which is what lets Tor put relays and sessions on separate circuits when the proxy isolates streams by credentials. Whether it does is a setting of the user's Tor, and the application cannot check it.
- The local web server binds to loopback only, checks `Host` and `Origin`, requires a 256-bit bearer token, and sends no CORS headers. Every response, including rejections, carries a strict content security policy with no inline scripts or styles, `Referrer-Policy: no-referrer`, and cross-origin isolation headers. Error text shown to the page has absolute file paths reduced to the file name.
- Requests are handled on separate threads (at most 16 at once). A client has 5 seconds to send the request head and 30 seconds for the body, so a client that sends bytes slowly cannot hold up the others. A running backup import does not block other requests; it only blocks work that would conflict with it.
- Files and directories the application creates are owner-only from the moment they exist, and a rename is followed by a flush of the directory entry, so a crash does not bring back the old file after a write that was reported as successful. A newly created file's own directory entry is not flushed.
- Chat messages are padded to one of four size classes before encryption, and an event carries no fixed marker and no session tag, so its length and contents do not identify this program or the exact message length. Subscription ids are random. Padding bytes must be zero and every other payload size is rejected.
- Each direction of a chat derives a new key every 1,000 messages (Noise Rekey), so one key does not protect a long conversation. The key in force is determined by the message's sequence number, so lost messages cannot put the two sides out of step.
- A session token expires after one hour without use and after twelve hours in any case. A new connection code, a logout, or an explicit disconnect ends sessions, so a copied token does not outlive the pairing it came from. At most four sessions exist at once.

## What it does not guarantee

- **Real-world identity.** A matching code proves the two sides agree on the keys, not who is behind them. The comparison is only as safe as the channel the users use.
- **Metadata privacy.** Relays see IP addresses (unless Tor is used), connection times, event timing and how many events a session sends. Chat message lengths are hidden only up to four size classes (256, 1024, 4096 and 8176 bytes of payload), so an observer still learns roughly how long a message is. The sequence number of each event is sent in the clear, which shows how many messages one side has sent. Events are ephemeral, but anyone subscribed to the same kind can see them.
- **Delivery.** A relay accepting an event does not mean the peer received or stored it. There are no read receipts and no offline queue.
- **Deletion.** Local deletion does not remove the peer's copy or any backup, and it is not forensic erasure.
- **Anonymity.** Tor mode covers only the relay connections. The external browser that opens message links is outside the application's control.
- **Endpoint security.** Malware, screen capture, memory dumps and physical access on the user's machine are not defended against.
- **Availability.** Public relays can disappear or filter events.

## Known weaknesses

These are known and documented, not hidden. Items are removed from this list only when the fix is recorded in [docs/security-fixes.md](docs/security-fixes.md).

1. **Legacy backup formats can still be imported after confirmation.** ADBACK2, ADBACK6, ADPACK1 and ADPACK2 are rejected by default and are accepted only when the user confirms a format-specific warning (see SF-002). ADBACK2 derives its key from the password alone and its messages are unsigned, so a user who confirms it for a file from an untrusted source can still be given forged history. Those messages are marked "서명 없음 · 미검증" (unsigned, unverified) in the history manager and the restore preview, but not yet in the live chat view.
2. **The access code is not protected by a secret.** The AD2 code contains its own wrapping key, so it is a per-code encoding of the seed, not encryption. Treat the code itself as the secret.
3. **Messages lost in transit stay lost.** Relay events are ephemeral and not retransmitted. A hole in the sequence now holds later messages back for ten seconds and is then skipped, with a notice in the chat that messages may have been lost, so the session no longer ends. The lost messages themselves are not recovered, and there are no delivery receipts to tell the sender. Only holes of up to 32 frames can be crossed; a larger jump still ends the session.
4. **Reconnects reuse the same relay topic and key**, which lets a relay link the sessions of one pair over time.
5. **The local history log has no generation id or end marker**, so a rolled-back or truncated file at a record boundary is not detected. An attacker who can replace every file together can always roll back; that case cannot be fully prevented on a single device.
6. **Secrets are not fully zeroized.** Key material is wrapped in `Zeroizing` where practical, but decrypted message text and some library-held keys are not wiped.
7. **No audit and limited fuzzing.** The test suite is extensive but the parsers have not been fuzzed.
8. **Dependency advisories.** `cargo audit` reports 9 `unsound` warnings for `heapless` 0.8.0, which `nostr` pulls in through `faster-hex`. They are not exploitable vulnerabilities in this application as far as I can tell, but I cannot remove them without upgrading the pinned `nostr` version.
9. **The confirmation code is a guess for a man in the middle, not a proof.** He needs the invite code, and then succeeds with probability 2^-40 per attempt and can try again. Each attempt needs a new connection and ends with the users seeing different codes.
10. **A peer on protocol version 2 fails with a generic error.** The two sides must run the same version, and the page cannot tell a version mismatch from a failed handshake.
11. **Relays are serviced while a person compares the code, but this is untested against a real relay.** The in-memory relay used by the tests never sends pings, so it cannot show whether answering them is what keeps a real connection open. The confirmation wait is bounded at five minutes on each side.

## Supply chain

Dependencies are pinned to exact versions and committed in `Cargo.lock`. The project builds from source; there are no prebuilt binaries. Anyone who can modify the source or the build can steal secrets before they are encrypted.
