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

_KDF_TO_CODE = {"argon2id": 1, "pbkdf2": 2}
_CODE_TO_KDF = {value: key for key, value in _KDF_TO_CODE.items()}


def _ensure_kdf_code(kdf: str) -> int:
    try:
        return _KDF_TO_CODE[kdf]
    except KeyError as exc:  # pragma: no cover - defensive guard
        raise ValueError(f"Unsupported KDF: {kdf}") from exc


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


def decode_payload(data: bytes) -> Dict[str, str]:
    """Decode binary payload data back into the JSON-friendly dictionary."""

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
    salt = data[end_version:end_salt]
    nonce = data[end_salt:end_nonce]
    ciphertext = data[end_nonce:end_ciphertext]

    return {
        "version": version_bytes.decode("utf-8"),
        "kdf": kdf,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def is_binary_payload(data: bytes) -> bool:
    """Return ``True`` if the data appears to use the binary payload format."""

    if len(data) < _HEADER.size:
        return False

    try:
        (
            format_version,
            kdf_code,
            version_len,
            salt_len,
            nonce_len,
            ciphertext_len,
        ) = _HEADER.unpack_from(data)
    except struct.error:  # pragma: no cover - defensive guard
        return False

    if format_version != FORMAT_VERSION or kdf_code not in _CODE_TO_KDF:
        return False

    expected_len = _HEADER.size + version_len + salt_len + nonce_len + ciphertext_len
    return expected_len == len(data)


__all__ = [
    "FORMAT_VERSION",
    "encode_components",
    "encode_payload",
    "decode_payload",
    "is_binary_payload",
]

