from __future__ import annotations

import base64

import pytest

from secure_qr_tool.payload import decode_payload, encode_components


@pytest.fixture()
def sample_components():
    return {
        "version": "v1",
        "kdf": "argon2id",
        "salt": b"s" * 16,
        "nonce": b"n" * 12,
        "ciphertext": b"c" * 32,
    }


def test_decode_payload_rejects_invalid_utf8_version(sample_components):
    binary = bytearray(encode_components(**sample_components))

    version_bytes = sample_components["version"].encode("utf-8")
    header_size = len(binary) - (
        len(version_bytes)
        + len(sample_components["salt"])
        + len(sample_components["nonce"])
        + len(sample_components["ciphertext"])
    )

    binary[header_size : header_size + len(version_bytes)] = b"\xff" * len(version_bytes)

    with pytest.raises(ValueError) as excinfo:
        decode_payload(bytes(binary))

    assert "UTF-8" in str(excinfo.value)


def test_decode_payload_rejects_truncated_binary(sample_components):
    binary = encode_components(**sample_components)
    truncated = binary[:-1]

    with pytest.raises(ValueError) as excinfo:
        decode_payload(truncated)

    assert "length mismatch" in str(excinfo.value)


def test_decode_payload_base64_roundtrip(sample_components):
    payload = decode_payload(encode_components(**sample_components))

    assert payload["version"] == sample_components["version"]
    assert payload["kdf"] == sample_components["kdf"]
    assert base64.b64decode(payload["salt"]) == sample_components["salt"]
    assert base64.b64decode(payload["nonce"]) == sample_components["nonce"]
    assert base64.b64decode(payload["ciphertext"]) == sample_components["ciphertext"]
