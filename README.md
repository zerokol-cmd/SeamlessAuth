# OQS Auth

OQS Auth is a Minecraft 1.7.10 mod that replaces the vanilla offline-mode login handshake
with a post-quantum signature challenge backed by [liboqs](https://github.com/open-quantum-safe/liboqs).
It optionally establishes an AES-256-GCM session key with the connecting client and supports
a KEM-based double-ratchet rekey for that session.

The server decides at runtime whether to require authentication, whether to negotiate a
session key, and whether to enable the double ratchet.

## Usage
Unimixins is required.
Install the jar in the Forge `mods` directory on the side(s) that should use it. A client
with the mod can still connect to vanilla servers.

### Configuration
The mod's options live in `oqsauth.cfg` under Forge's `config/` directory after the first
launch.

| Option | Default | Description |
| --- | --- | --- |
| `general.signatureAlgorithm` | `ML-DSA-65` | Post-quantum signature algorithm. |
| `general.kemAlgorithm` | `ML-KEM-768` | KEM used for session keys and ratchet rekey. |
| `general.debugLogging` | `false` | Log extra information. |
| `client.keystorePath` | `oqsauth.keystore` | Single client keystore file. |
| `server.keyDatabasePath` | `oqsauth.keys` | Single server key database file. |
| `server.requireLoginAuth` | `true` | Demand a signed challenge from the client. |
| `server.implicitRegistration` | `true` | Pin the first key seen for an unknown username. |
| `server.enableSessionEncryption` | `false` | Establish an AES-256-GCM session key. |
| `server.enableSessionRatchet` | `false` | Allow KEM double-ratchet rekey for the session. |

### Server key database
The server stores known users in a single text file:

```
<username> <uuid> <algorithm> <base64(public_key)>
```

The `algorithm` and public-key fields may be omitted to pre-pin a UUID for a username
without registering a key yet. Entries with only a UUID will be filled in the first time
that user connects (when `implicitRegistration` is true).

### Commands
- `/oqsauth reload-config` (client) reloads `oqsauth.cfg`.
- `/oqsauth_server reload-config` and `/oqsauth_server reload-keys` (server, op level 4) reload
  the configuration and the on-disk key database respectively.

## Protocol overview
1. **Server hello.** After the vanilla `LoginStart`, the server sends a `ServerHello` containing
   flags, the signature algorithm, the KEM algorithm, a 64-byte random challenge (if auth is
   required), and an ephemeral KEM public key (if session encryption is enabled).
2. **Client auth response.** The client encapsulates against the server's KEM public key (if any),
   signs `SHA-256("oqs-auth-v1" || flags || sigAlgo || kemAlgo || challenge || serverKemPub ||
   kemCiphertext || username)` with its long-term identity, and sends the public key, the
   signature, and the KEM ciphertext back to the server.
3. **Server verification.** The server verifies the signature against the pinned identity in
   the key database (pinning the new public key when implicit registration is enabled and the
   user is unknown). It decapsulates the KEM ciphertext to recover the shared secret, then
   derives a 32-byte root key with `HKDF-SHA256(transcript, sharedSecret, "oqs-auth-root")`.
4. **Session.** Both sides derive directional 32-byte chain keys from the root key. Messages
   are encrypted with `AES-256-GCM`; each message uses a fresh per-message subkey/nonce
   derived from the chain key via HMAC-SHA256. When the ratchet is enabled, either side can
   include a ratchet header (a fresh KEM public key plus a KEM ciphertext encapsulated against
   the peer's current public) to advance the root key.

## Security notes
- The signed transcript binds the signature to the challenge, the server's KEM public key, the
  client's KEM ciphertext, and the username, preventing relay or splicing attacks across
  concurrent connections.
- Implicit registration is *trust on first use*. With `implicitRegistration = false`, only
  pre-pinned users can authenticate.
- The AEAD message key changes every message, so AES-GCM nonce reuse cannot occur.
- The double ratchet provides forward secrecy (the previous chain key is discarded after every
  message) and post-compromise security (a fresh KEM exchange replaces the root key).
- Client secret keys are stored on disk with owner-only POSIX permissions when supported by
  the filesystem.

## Contributing
Treat any forge / git host as a mirror. Send patches to the same channels as before.
