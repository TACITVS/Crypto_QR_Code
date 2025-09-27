# Secure QR Payload Protocol

This document specifies the format and procedures that the Secure QR Code Tool
uses to transform arbitrary UTF-8 text into an authenticated, encrypted payload.
The intent is to make payloads interoperable across implementations, regardless
of programming language or operating system.

## Notation

The keywords **MUST**, **MUST NOT**, **SHOULD** and **MAY** follow the meanings
assigned by RFC 2119. All multi-byte integers are represented in network byte
order (big endian) unless stated otherwise. When the text refers to base64 it
uses the RFC 4648 “standard” alphabet without padding characters removed.

## Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Cipher | AES-256-GCM | Authenticated encryption with a 128-bit tag |
| Key derivation | Argon2id (default) or PBKDF2-HMAC-SHA256 | Generates the 256-bit AES key |
| Argon2 parameters | Implementation defined (defaults: time cost 3, memory 128 MiB, parallelism 2) | MUST be recorded out-of-band when deviating from defaults |
| PBKDF2 iterations | Implementation defined (default 600,000) | MUST be recorded with the payload when deviating from the default |
| Salt size | 16 bytes | MUST be generated from a cryptographically secure RNG |
| Nonce size | 12 bytes | MUST be generated from a cryptographically secure RNG |
| Encoding | UTF-8 | Payload plaintext and metadata are UTF-8 |

An implementation MAY choose higher iteration counts or longer salts, provided
that all verifiers understand the configuration. Reducing the iteration count or
the nonce length is NOT permitted.

## Payload container

Encrypted payloads are serialised as JSON dictionaries when exported as text
files or transported over traditional channels. A conforming implementation MUST
produce the following keys:

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Application or protocol version identifier |
| `salt` | string | Base64 encoded salt used for key derivation |
| `nonce` | string | Base64 encoded AES-GCM nonce |
| `ciphertext` | string | Base64 encoded AES-GCM ciphertext (includes tag) |
| `kdf` | string | Lowercase algorithm label (`argon2id` or `pbkdf2`) |

No additional top-level keys are required, but producers MAY include metadata
such as the Argon2 parameters or PBKDF2 iteration count under vendor-specific
names. Consumers MUST ignore unrecognised fields. The JSON dictionary MUST be
encoded using UTF-8 when stored as text.

### Example payload

```json
{
  "version": "1.0",
  "salt": "9qrzpq4vERD1qzNNzjl4mA==",
  "nonce": "bI8WmM4tF6pP2OG4",
  "ciphertext": "uSBJ8pUTj8VhQ0Wvm0AxHkXaJq62g2jAh5q0VK8QG80=",
  "kdf": "argon2id"
}
```

All base64 strings MUST be decoded before use. The ciphertext value includes the
16-byte authentication tag produced by AES-GCM.

## Encryption procedure

Given a UTF-8 string `plaintext` and a password `password`, an implementation
MUST perform the following steps:

1. Generate a random 16-byte salt (`salt`).
2. Derive a 32-byte key (`key`) using the configured KDF (Argon2id by default,
   PBKDF2 when explicitly selected) with the salt and KDF-specific parameters on
   the UTF-8 bytes of `password`.
3. Generate a random 12-byte nonce (`nonce`).
4. Encrypt the UTF-8 bytes of `plaintext` with AES-256-GCM using `key`, `nonce`
   and the additional authenticated data (AAD) described below, producing
   `ciphertext` (which includes the GCM authentication tag).
5. Base64 encode `salt`, `nonce` and `ciphertext`.
6. Produce a JSON dictionary matching the schema described above.

The salt and nonce MUST be unique per encryption invocation. Reusing either
value with the same password leaks information and voids the integrity
guarantees provided by AES-GCM.  When JSON output is required the payload is
identical to previous versions of the tool to preserve compatibility.

## Decryption procedure

Given a JSON payload and a password, a conforming implementation MUST:

1. Parse the JSON dictionary using UTF-8.
2. Verify that the `salt`, `nonce` and `ciphertext` fields exist. If any are
missing the payload MUST be rejected.
3. Base64 decode the three fields into raw byte strings.
4. Determine the key derivation function from the `kdf` field (falling back to
   the configured default if omitted) and re-derive the AES key using the same
   parameters as the encrypting side.
5. Attempt AES-256-GCM decryption with the derived key, decoded nonce and the
   additional authenticated data (AAD) described below.
6. If the AES-GCM authentication tag is invalid, the implementation MUST reject
the payload and report an error.
7. Convert the decrypted byte sequence to a UTF-8 string to obtain the original
plaintext.

Consumers SHOULD surface the `version` field to end users and MAY use it to
select alternative parameters if the protocol evolves.  When the payload is
embedded in the binary QR container (see below) the decoder MUST reconstruct
this JSON dictionary before attempting decryption.

### Binary QR container

QR codes generated by the Secure QR Code Tool contain a binary framing layer to
reduce size and avoid ambiguities introduced by text-mode transports. The
framing layout is defined as:

```
Offset  Size  Field
0       1     Format version (currently 0x01)
1       1     KDF identifier (0x01 = argon2id, 0x02 = pbkdf2)
2       2     Length of UTF-8 encoded `version`
4       2     Length of raw `salt`
6       2     Length of raw `nonce`
8       4     Length of raw `ciphertext`
12      …     Variable-length payload sections in the order above
```

All integers are big endian.  Trailing ASCII whitespace MAY be present when QR
payloads pass through text channels and MUST be ignored by decoders.  The binary
segments are concatenated without padding and correspond to the same material as
the JSON representation.

### Additional authenticated data

Implementations MUST supply deterministic AAD to AES-GCM to bind protocol
metadata to the encrypted payload. The AAD is a UTF-8 JSON object serialised
with sorted keys and no whitespace, containing the following fields:

```
{"cipher":"AES-256-GCM","kdf":"<kdf>","version":"<version>"}
```

Any change to the cipher identifier, protocol version or advertised KDF will
invalidate the authentication tag and MUST cause decryption to fail. This guards
against downgrade attacks where an adversary attempts to replay ciphertext under
different algorithm choices.

## QR code considerations

When encoding payloads into QR codes, producers SHOULD emit the binary container
described above.  Implementations MAY fall back to UTF-8 JSON if binary
encoding is not available, but doing so increases QR density and is susceptible
to whitespace corruption.  In both cases, providing an external checksum (for
example SHA-256 of the encoded payload) enables recipients to validate scans
before attempting decryption.

## Interoperability checklist

Implementers can verify compliance by following this checklist:

- [ ] Ensure salts and nonces come from a cryptographically secure RNG.
- [ ] Confirm that the PBKDF2 iteration count matches the sender’s configuration.
- [ ] Decode base64 values prior to decryption.
- [ ] Enforce AES-GCM authentication tag validation.
- [ ] Treat all JSON as UTF-8 text and preserve fields exactly as received.

Following this specification guarantees that any party holding the password can
reproduce the encryption and decryption process using standard cryptographic
libraries.
