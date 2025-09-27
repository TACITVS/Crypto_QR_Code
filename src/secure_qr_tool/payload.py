"""Binary payload serialisation utilities."""
from __future__ import annotations

import base64
import binascii
import struct
from typing import Dict, Mapping

FORMAT_VERSION = 1
"""Current binary payload format version."""

_HEADER = struct.Struct(">BBHHHI")
"""Header structure: version, kdf enum, version len, salt len, nonce len, ciphertext len."""

_IGNORABLE_SUFFIX = {0x00, 0x09, 0x0A, 0x0D, 0x20}
"""Suffix bytes ignored when decoding binary payloads.

The QR decoding libraries used by the application occasionally append a
trailing NUL byte (``0x00``) to the extracted binary data.  The original
implementation only stripped ASCII whitespace which caused legitimate QR
payloads to be rejected as malformed.  Including ``0x00`` in the ignored
set keeps the strict length checks for the actual payload while being
resilient to this common decoder quirk.
"""

_KDF_TO_CODE = {"argon2id": 1, "pbkdf2": 2}
_CODE_TO_KDF = {value: key for key, value in _KDF_TO_CODE.items()}


def _ensure_kdf_code(kdf: str) -> int:
    try:
        return _KDF_TO_CODE[kdf]
    except KeyError as exc:  # pragma: no cover - defensive guard
        raise ValueError(f"Unsupported KDF: {kdf}") from exc


def _rstrip_ignorable(data: bytes) -> bytes:
    """Strip ASCII whitespace permitted at the end of a binary payload."""

    end = len(data)
    while end and data[end - 1] in _IGNORABLE_SUFFIX:
        end -= 1
    return data[:end]


def encode_components(
    *,
    version: str,
    kdf: str,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    """Pack raw payload components into the binary payload format."""

    version_bytes = version.encode("utf-8")
    header = _HEADER.pack(
        FORMAT_VERSION,
        _ensure_kdf_code(kdf),
        len(version_bytes),
        len(salt),
        len(nonce),
        len(ciphertext),
    )
    return b"".join((header, version_bytes, salt, nonce, ciphertext))


def encode_payload(payload: Mapping[str, str]) -> bytes:
    """Encode an existing JSON payload dictionary into the binary format."""

    required = ("salt", "nonce", "ciphertext")
    for field in required:
        if field not in payload:
            raise ValueError(f"Missing field in payload: {field}")

    try:
        salt = base64.b64decode(payload["salt"])
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
    except (TypeError, binascii.Error) as exc:
        raise ValueError("Payload contains invalid base64 data") from exc

    version = payload.get("version", "")
    kdf = payload.get("kdf", "argon2id")

    return encode_components(
        version=version,
        kdf=kdf,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def decode_components(container: bytes) -> Dict[str, object]:
    """Parse ``container`` into its raw payload parts.

    The returned dictionary mirrors :func:`encode_components` but keeps the salt,
    nonce and ciphertext as :class:`bytes` so that callers can decide how to
    serialise them (e.g. base64 for JSON compatibility).
    """

    data = _rstrip_ignorable(container)
    if len(data) < _HEADER.size:
        raise ValueError("Binary payload is truncated")

    (
        format_version,
        kdf_code,
        version_len,
        salt_len,
        nonce_len,
        ciphertext_len,
    ) = _HEADER.unpack_from(data)

    if format_version != FORMAT_VERSION:
        raise ValueError(f"Unsupported payload format version: {format_version}")

    try:
        kdf = _CODE_TO_KDF[kdf_code]
    except KeyError as exc:
        raise ValueError(f"Unsupported KDF code: {kdf_code}") from exc

    offset = _HEADER.size
    end_version = offset + version_len
    end_salt = end_version + salt_len
    end_nonce = end_salt + nonce_len
    end_ciphertext = end_nonce + ciphertext_len


    if end_ciphertext != len(data):
        raise ValueError("Binary payload length mismatch")

    version_bytes = data[offset:end_version]
    try:
        version = version_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Version field is not valid UTF-8") from exc

    return {
        "version": version,
        "kdf": kdf,
        "salt": data[end_version:end_salt],
        "nonce": data[end_salt:end_nonce],
        "ciphertext": data[end_nonce:end_ciphertext],
    }


def decode_payload(data: bytes) -> Dict[str, str]:
    """Decode binary payload data back into the JSON-friendly dictionary."""

    components = decode_components(data)
    return {
        "version": components["version"],
        "kdf": components["kdf"],
        "salt": base64.b64encode(components["salt"]).decode("ascii"),
        "nonce": base64.b64encode(components["nonce"]).decode("ascii"),
        "ciphertext": base64.b64encode(components["ciphertext"]).decode("ascii"),
    }


def is_binary_payload(data: bytes) -> bool:
    """Return ``True`` if the data appears to use the binary payload format."""

    try:
        decode_components(data)
    except ValueError:
        return False
    return True


__all__ = [
    "FORMAT_VERSION",
    "encode_components",
    "encode_payload",
    "decode_components",
    "decode_payload",
    "is_binary_payload",
]
