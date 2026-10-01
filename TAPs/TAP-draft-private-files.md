---
tap: TBD
title: Encrypted Private Files in a Container
description: A file format and read/write rules for keeping a holder's private data, encrypted with a passkey, in their own circuit container.
author: JogJohgoeg (@JogJohgoeg)
discussions-to: https://github.com/TapeOutProtocol/TAPs/issues/13
status: Draft
type: Application
created: 2026-09-30
requires: TAP-10, WebAuthn Level 3 (PRF extension)
license: CC0-1.0
---

# TAP-TBD: Encrypted Private Files in a Container

## Summary

A way for an app to keep your private data in your own circuit container, locked with a passkey so that nobody else, not even a site that tricks you into signing something, can read it.

## Abstract

This TAP defines how an application stores a holder's private data as a file in the holder's own circuit container (TAP-10 §7): the path, how the encryption key is derived from a WebAuthn passkey through the PRF extension, the byte layout of the file, which binds the ciphertext to its chain, container and path, who may write it, and the checks a client makes when it reads it, including detection of an old file written back unchanged (rollback), of a downgrade to an older format, and of two devices writing close together. It adds no contract and changes nothing in TAP-10. The content of the file and how an application merges two copies are left to the application.

## Motivation

Every file in a container is public for ever: its bytes, size, hash and write time. Applications that want to keep a user's own state in the user's own container (a two-factor authenticator's secrets, notes, settings, an agent's memory) must encrypt it, and today each invents its own scheme.

The obvious scheme, deriving the key from a wallet signature over a fixed text, is unsafe for this purpose: any site that persuades the holder to sign the same text obtains the key, and the ciphertext it opens is already public and cannot be withdrawn. The reference deployment (see Reference Implementation) used that scheme until 2026-09-29 and replaced it after a phishing report.

Encryption alone is not enough either. Whoever can write the container (the holder, or an operator the holder authorised) can write an old ciphertext back unchanged, and it still decrypts. One public node can serve a stale file. A client can be led to read an older, weaker format. Two devices of the same holder that write close together overwrite each other, and naive checks then report a failure or a rollback that did not happen. Each of these occurred in the reference deployment's testing. This TAP fixes one answer to each, so that files written by one application can be read and checked by any other that follows it.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

### 1. Terms

- **Holder**: the current owner of the circuit whose container holds the file (TAP-10 §1).
- **Private file**: a file defined by this TAP.
- **Client**: software that reads or writes private files for the holder.
- **Operator**: an address authorised by the holder with `SiteRegistry.setOperator` to write the container on the holder's behalf.
- **Passkey**: a WebAuthn discoverable credential; its **RP ID** is the relying party identifier it is bound to, and its **credential ID** is written base64url without padding (RFC 4648 §5).
- **Strict agreement**: the read rule of TAP-10 §5.2: sent to every configured node, adopted only when all answers agree and come from enough operators.
- `‖` is byte concatenation; `len(x)` is one byte holding the length of `x`; strings are UTF-8.

### 2. Path

1. A private file **MUST** be stored at `.private/<app-id>/<name>`, where `<app-id>` and `<name>` each match `[a-z0-9-]{1,32}` (the file name may also contain one `.`).
2. Private files are data, not pages. Shells **SHOULD NOT** render paths under `.private/` as pages and **MAY** answer them as not found.
3. The file's `contentType` is `application/octet-stream` and its `sha256Hash` **MUST** be the SHA-256 of the file bytes (never all zeros, TAP-10 §7.1 item 5).

### 3. Passkey and key

1. **PRF input.** `P = SHA-256("tap-private-files/prf/v1")`, that is `0x0ac22e54f858c69e60e07fdf6fccdf8b915dde06b5d5a8e5c815b34b7dfe52f1`. Every create and get ceremony **MUST** request `extensions.prf.eval.first = P`.
2. **RP ID.** The RP ID **MUST** be the exact host the client is served from (`location.hostname`), set explicitly as `rp.id` and `rpId`, and **MUST NOT** be a parent domain of it. On a gateway whose domain is not on the Public Suffix List (TAP-10 §8.8), a parent-domain RP ID would let every site on that gateway request the same passkey. A site reachable under several hosts (TAP-10 §3.3) **SHOULD** use one canonical host for private files, chosen by the holder; it is recorded in the file as `H` (§4).
3. **Creating a passkey.** `user.id` **MUST** be the 20 bytes of the holder address, so that a device with no wallet can find the container from the passkey alone. `authenticatorSelection` **MUST** require a resident key and user verification. `excludeCredentials` **MUST** list every credential ID the client knows for this holder and RP ID: creating a second passkey with the same RP ID and `user.id` silently replaces the first in common passkey providers, and every file sealed to the first would become unreadable. If the result reports `prf.enabled == false`, the passkey **MUST NOT** be used. A provider that returns no PRF result at creation is asked once more with a get ceremony.
4. **Using a passkey.** A get ceremony **MUST** set `userVerification: "required"`. A client that knows the credential ID **MUST** name it in `allowCredentials`.
5. **Key.** With `R` the 32-byte PRF output, `a` the holder address in lower-case hexadecimal with `0x`, and `p` the file's path (`.private/<app-id>/<name>`):

   ```
   K = HKDF-SHA256(IKM = R, salt = "tap-private-files/v4|" ‖ a, info = "tap-private-files/key|" ‖ p, L = 32)
   ```

   `K` is an AES-256-GCM key. A wallet signature **MUST NOT** be an input to `K`. Because `p` is in `info`, applications sharing one passkey on one RP ID derive unrelated keys, and no file can be opened under another path.

### 4. File format

```
file = 0x04 ‖ len(C) ‖ C ‖ len(H) ‖ H ‖ IV ‖ AES-256-GCM(K, IV, A, deflate-raw(J))
A    = "tap-private-files/v4" ‖ "|" ‖ n ‖ "|" ‖ c ‖ "|" ‖ p ‖ "|" ‖ a ‖ "|" ‖ base64url(C) ‖ "|" ‖ H
```

- `n` is the chain ID in decimal and `c` the container address in lower-case hexadecimal with `0x`, both of the container that holds the file; `p` and `a` are as in §3.5. A file copied to another path, container or chain therefore does not open.
- `C` is the credential ID bytes and `H` the RP ID; each **MUST** be at most 255 bytes, otherwise the client **MUST NOT** write the file. `base64url(C)` in `A` is the canonical encoding of the bytes in the header; a writer **MUST** compute `A` from the bytes it writes.
- `IV` is 12 bytes, **MUST** be fresh random for every write, and the 16-byte tag ends the file.
- `J` is a UTF-8 JSON object compressed with raw DEFLATE (RFC 1951). It **MUST** have a member `at`: the generation time in milliseconds, taken from the latest block of the container's chain when sealing, or from the device clock only if no node answers (§8.4). Other members are defined by the application.
- A written file **MUST NOT** exceed 262,144 bytes. A reader **MUST** refuse a file above that size, and **MUST** stop decompressing and refuse beyond 8,388,608 bytes of output.

### 5. Writers

1. The holder **MAY** write directly with `SiteRegistry.putFile(address container, string path, string contentType, bytes32 sha256, bytes data)` (selector `0xfab2ed82`) and `appendChunk(address container, string path, uint256 index, bytes data)` (selector `0xe2b51347`), in chunks of at most 24,000 bytes.
2. A device without a wallet **MAY** write through an operator key kept on that device. The holder authorises it with `setOperator(address container, address operator, uint256 ttl)` (selector `0xc88cb026`), `ttl` at most 30 days; `ttl = 0` revokes. The contract keeps one operator per container, readable with `operatorOf(address)` (`0x636f35d3`) and `operatorUntil(address)` (`0xc85cf62b`).
3. An operator can change every file of the container. Before asking the holder to authorise an operator, a client **MUST** check under strict agreement at one pinned block that the container holds no path outside `.private/`, and **MUST** refuse otherwise. It **MUST** show the operator address and the container, and **MUST** show any other operator currently in place, with a way to revoke it.
4. A client **MUST NOT** keep an operator's private key unencrypted in browser storage.

### 6. Writing

1. Read the current file (§7). If it exists and differs from the last version this client wrote or read, open it and merge it into the local data (application-defined) before writing. A file that cannot be opened (§7.4) **MAY** be overwritten only after the holder confirms. A client that has not yet held any data on this device (a new device restoring) **MUST NOT** offer to overwrite: the file is more likely unreadable because the passkey has not synced yet.
2. Reuse the passkey named in the current file when this device can use it; create one (§3.3) only when there is none.
3. If the application locked or cleared its local data while steps 1–2 were waiting, the client **MUST NOT** seal and write: an empty local copy would replace the real file.
4. After the last transaction's receipt, read `fileInfo` under strict agreement at a pinned block no lower than the receipt's block. If the answer is this file's SHA-256, the write is confirmed. If it is a different, later file and the receipt of this client's `putFile` contains the `FileSet` event (§8.2) with this file's SHA-256, the write happened and was then replaced by another writer; the client **MUST NOT** report a failure and **SHOULD** read and merge the newer file. Otherwise (including when strict agreement fails) the client **MUST** warn that the write may not be on chain.

### 7. Reading

1. `fileInfo` and the content **MUST** be read at one pinned block (TAP-10 §5.3), and `fileInfo` **MUST** be read under strict agreement. If it is rejected or unavailable, the client **MUST NOT** open the file; it **MAY** retry after a few seconds.
2. The implementation check of TAP-10 §6.1 applies.
3. Length and SHA-256 are verified as in TAP-10 §7.1 item 4.
4. The file cannot be opened when: the first byte is not `0x04` (or, at the legacy path only, `0x03`, see Backwards Compatibility); the header is truncated; `H` is not the RP ID the client runs under; the passkey is not available on this device; or decryption, decompression or JSON parsing fails. These cases, a hash mismatch and a size above the limit are all reported as "cannot open", so the holder can overwrite the file (§6.1). One exception: when `H` names another host of the same site, the file is probably genuine; the client **MUST NOT** offer to overwrite it and **SHOULD** tell the holder to open the site on that host.
5. **Downgrade.** A client **MUST NOT** open a file under `.private/` in any version other than `0x04`. At the legacy path of Backwards Compatibility, a client that has seen `0x03` there, or that holds a passkey for this holder, **MUST NOT** open an older version.

### 8. Rollback

Every write uses a fresh IV, so the same file bytes legitimately appear on chain once. A client **MUST** apply all of the following and **MUST** warn the holder when any fires. The warning **MUST** stay pending until the holder has seen it (it must survive navigation and re-rendering). Local data is never removed because of a rolled-back file; the merge still applies.

1. **Seen hashes.** The client keeps, per container, the SHA-256 of the last 30 or more files it read or wrote. A current file whose hash is in that list, but is not the most recent entry, is a rollback. No clock is involved.
2. **Write events.** The client scans the container's recent write events, `FileSet(address indexed container, string path, uint32 size, bytes32 sha256, string contentType)` (topic `0x13b9b0f05b22c496a9d9a29e7041c56c04670dc98ab327448870f18eb07b6773`), for this path over at least the last 3,900 seconds, converting seconds to blocks with the chain's measured block interval. The current hash appearing earlier with a different hash written in between is a rollback. If the scan could not cover the whole range and found nothing, the result is unknown, not "no rollback".
3. **Generation time.** With `g` = `at` of the opened file and `u` = `updatedAt` from `fileInfo` × 1000, clamp `g` to at most `u + 600000`. It is a rollback when `u − g > 3600000`, or when `g` is more than 600,000 ms older than the latest generation time this client has seen for the container (also clamped).
4. Writers take `at` from the latest block, not the device clock, because readers compare it with block time: a slow writer clock made every reader warn, and a fast one, once recorded as the latest seen, made every later honest file look older.

### 9. Independent copy, device and site storage

1. An application **MUST** offer the holder a copy of the data that depends neither on the passkey nor on the RP ID's domain (for example an export kept offline, or a format another application can import), and **SHOULD** offer it after the first write. Losing every copy of the passkey, or losing use of the RP ID's domain, otherwise loses the file (Security Considerations).
2. A client **SHOULD** offer an application lock for the local copy and **MUST** clear decrypted data, keys and operator keys from memory when it locks.
3. When a private file is restored on a new device, the client **SHOULD** say that the site's storage in one browser (or a home-screen web app, which on iOS has separate storage) does not carry over to another.

## Rationale

- **Passkey, not wallet signature.** A passkey's PRF output is bound by the browser to the RP ID and needs user verification; a phishing origin cannot request it. A wallet signature over a fixed text can be requested by any origin, and EIP-4361 warnings are not universal. The wallet keeps the role it is good at: deciding who may write.
- **Labels.** The labels in §3 and §4 name the format, not an application and not a TAP number. The reference deployment's labels (`authenticator-backup-…`, `chain-backup-passkey`) are kept only for its `0x03` file (Backwards Compatibility).
- **Path, container and chain in the key and the additional data.** With a fixed PRF input and one passkey per holder and RP ID (`user.id` is the holder address and `excludeCredentials` prevents a second one), every application on an RP ID would otherwise derive the same key, and a party with write access could copy a file to another path, and have it opened by another application, without detection. `p` in `info` separates keys per path; `n`, `c` and `p` in `A` reject a moved file even under the same key.
- **Holder address in the salt and the additional data.** A file cannot be moved to another holder's container and still open, and the same passkey used by several holders on one site derives unrelated keys.
- **Comparison with TAP-10 §14.2.** TapeSend derives its key from a wallet signature over a fixed EIP-4361 text. The text names `www.tapesend.com`, so EIP-4361-aware wallets warn when another origin asks for it; wallets that do not check, and WalletConnect origins, which are self-declared, do not. TAP-10 therefore requires the official client to be served only from that origin. A passkey's PRF output is bound to its RP ID by the browser itself, independent of the wallet, but it is bound to a host: the key is unavailable on any other host, and whoever controls the RP ID's domain controls access (Security Considerations). This TAP does not change TapeSend.
- **"Cannot open" means "may overwrite".** Anyone with write access can write bytes that do not decrypt. If such bytes were a hard error, one write would stop the holder from ever saving again.
- **Three rollback checks.** The seen list needs no clock but only knows what this device saw; the event scan catches replays on a fresh device but only covers a recent window (public nodes limit event queries); the generation time covers older replays. Together they leave no window between them.
- **Confirming under strict agreement after writing.** The node that sent the transaction also reports its receipt; a lying node could claim a write that never happened, and strict agreement (rather than default agreement) is the rule TAP-10 uses where a few colluding nodes could otherwise mislead the client.

## Backwards Compatibility

The reference deployment predates this TAP. It stores its file at `.authenticator/backup.bin` (the **legacy path**) in version `0x03`, which differs from `0x04` only as follows:

```
P = SHA-256("authenticator-backup-prf-v1")      = 0x9daa7a47279ba37c24cd44e7bf254ab1fc3a6ff8af7a67ae497dd760d5e91d82
K = HKDF-SHA256(IKM = R, salt = "authenticator-backup-v3:" ‖ a, info = "chain-backup-passkey", L = 32)
A = a ‖ "|" ‖ base64url(C) ‖ "|" ‖ H
```

`0x03` binds neither the path nor the container, so a client **MAY** read it only at the legacy path and **MUST NOT** write it anywhere else. When the application moves to `0x04` it writes `.private/authenticator/backup.bin` and can obtain both PRF outputs in one ceremony (`eval.first` and `eval.second`). The deployment also reads, but no longer writes, versions `0x01` and `0x02`, whose key came from a wallet signature; they are outside this TAP and §7.5 prevents a downgrade to them.

## Test Cases

`assets/tap-draft-private-files/vectors.json`, produced and checked by `assets/tap-draft-private-files/vectors.mjs` (`node vectors.mjs check`). They cover, for `0x04`: the PRF input, key derivation, the additional data, opening a valid file, and files that fail to open (a flipped byte, another address, another path, another container, another chain, another key, an unknown version, a `0x03` file); for `0x03`: the same vectors as the deployed implementation, which opens and rejects the same files; and the canonical form of a non-canonical credential ID.

## Reference Implementation

The TapeOut Authenticator, served from `288.732.tape` on BNB Smart Chain (container `0x1b21a2d9de0d4a7242f604c37290946c383937da`), as stored on chain at block 124,895,699. Its files are fixed by their SHA-256 in `SiteRegistry`:

| File | SHA-256 |
|---|---|
| `wallet.js` (format, key, limits) | `020ebb37b9c367bcf206b4fd1ac4be860c79163645a096541ac5f6ab8a800094` |
| `passkey.js` (PRF, create, discover) | `e4639316145ae0dfa1426a6bfc237c3bbcd548ed05c9e4e8fec704b719784649` |
| `tapeout.js` (reads, node agreement, write events) | `b6a795942a1ab30596a472100ce65c7d1ac3fee6b38eb8be3a1ece8a4562ea26` |
| `device.js` (operator key) | `640b72363954f9006bea0e50002a53c30647d29d7d78667812482cc62de1df4f` |
| `app.js` (writing, reading, rollback, downgrade) | `354c660de7d4d3b071acdbc2bb08f1c55bdd431b7b20820329359ea79c42d8d5` |

It writes the `0x03` format at the legacy path (Backwards Compatibility) and does not yet write `0x04`; `vectors.mjs` is the reference for `0x04`. It offers an independent copy (§9.1) as an export of QR codes in the Google Authenticator migration format.

## Security Considerations

- **Protected:** the content, against anyone without the passkey, including a phishing site that obtains a wallet signature, the holder's other contracts and public nodes, and other applications on the same RP ID; gateways only as far as the next bullet allows; the integrity of the content and its location (AES-GCM with the chain, container, path, address, credential ID and RP ID as additional data); rollback and downgrade by a party with write access, which are detected and reported.
- **Not protected:** the file's existence, size and write times, which are public; availability, since whoever can write the container can delete or overwrite the file; a device on which the application runs unlocked, where malware or a malicious browser extension can read the local copy.
- **Whoever controls the RP ID's domain controls access to the passkey.** When the RP ID is a third-party gateway host, as in the reference deployment, the gateway's operator can serve code on that host that requests the PRF output the next time the holder unlocks, and then read every file sealed with it. If the domain lapses, the holder can no longer use the passkey, and whoever registers the domain next can request it. TAP-10's file verification does not help here: it constrains what an honest gateway serves, not what the domain's controller can serve. Holders who do not trust a gateway's operator should use a host they control as the canonical host (§3.2).
- **Losing the passkey** (every synced copy) or the use of the RP ID's domain makes the file unreadable. This is why §9.1 requires an independent copy.
- **Synced passkeys** follow the holder's Apple or Google account: whoever controls that account and a device can open the file. Holders who need more can use a device-bound authenticator, at the cost of a single point of loss.
- **RP ID.** A passkey works only on its RP ID. A site reachable under several host names (TAP-10 §3.3) sees different passkeys on each; a client should tell the holder which host a file belongs to (§7.4). A parent-domain RP ID is forbidden (§3.2) because it would share one passkey, and with the fixed PRF input one key per path, among all sites under that domain.
- **Operators** can rewrite every file in the container, which is why §5.3 limits them to containers holding only private files, and why the operator key must not be stored in the clear.
- **Code.** The client decrypts in the page, so the page's code must be what the holder expects; TAP-10's file verification covers what the gateway serves, not what an application later does with the key.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE).
