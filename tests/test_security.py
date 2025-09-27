from __future__ import annotations

import base64
import json

import pytest

from secure_qr_tool.config import AppConfig
from secure_qr_tool.payload import decode_payload, encode_payload, is_binary_payload
from secure_qr_tool.security import CryptoManager, MnemonicManager, SecureString


@pytest.fixture()
def config() -> AppConfig:
    return AppConfig(
        pbkdf2_iterations=10_000,
        argon2_time_cost=1,
        argon2_memory_cost_kib=32_768,
        argon2_parallelism=1,
    )


@pytest.fixture()
def pbkdf2_config() -> AppConfig:
    return AppConfig(kdf_algorithm="pbkdf2", pbkdf2_iterations=10_000)


def test_secure_string_clears_buffer():
    secret = SecureString("top secret")
    assert secret.get() == "top secret"
    secret.clear()
    assert secret.get() == ""


def test_encrypt_roundtrip(config: AppConfig):
    crypto = CryptoManager(config)
    password = SecureString("A" * config.min_password_length)
    payload_dict, payload_bytes = crypto.encrypt(SecureString("mnemonic words"), password)
    assert set(payload_dict) == {"salt", "nonce", "ciphertext", "version", "kdf"}
    assert isinstance(payload_bytes, bytes)
    assert is_binary_payload(payload_bytes)
    assert encode_payload(payload_dict) == payload_bytes
    assert decode_payload(payload_bytes) == payload_dict

    decrypted = crypto.decrypt(payload_dict, password)
    assert decrypted.get() == "mnemonic words"
    decrypted_bytes = crypto.decrypt(payload_bytes, password)
    assert decrypted_bytes.get() == "mnemonic words"


def test_decrypt_rejects_invalid_payload(config: AppConfig):
    crypto = CryptoManager(config)
    password = SecureString("A" * config.min_password_length)

    with pytest.raises(ValueError):
        crypto.decrypt({"salt": ""}, password)


def test_decrypt_rejects_invalid_base64(config: AppConfig):
    crypto = CryptoManager(config)
    password = SecureString("A" * config.min_password_length)

    payload = {
        "salt": "?bad",
        "nonce": "?bad",
        "ciphertext": "?bad",
    }

    with pytest.raises(ValueError) as excinfo:
        crypto.decrypt(payload, password)

    assert str(excinfo.value) == "Payload contains invalid base64 data"


def test_decrypt_with_wrong_password(config: AppConfig):
    crypto = CryptoManager(config)
    password = SecureString("A" * config.min_password_length)
    payload, _ = crypto.encrypt(SecureString("secret"), password)

    wrong_password = SecureString("B" * config.min_password_length)
    with pytest.raises(ValueError) as excinfo:
        crypto.decrypt(payload, wrong_password)

    assert "authentication error" in str(excinfo.value)


def test_decrypt_with_invalid_nonce_length(config: AppConfig):
    crypto = CryptoManager(config)
    password = SecureString("A" * config.min_password_length)
    payload, _ = crypto.encrypt(SecureString("secret"), password)
    payload["nonce"] = base64.b64encode(b"short").decode("ascii")

    with pytest.raises(ValueError) as excinfo:
        crypto.decrypt(payload, password)

    assert "Nonce" in str(excinfo.value) or "between" in str(excinfo.value)


def test_decrypt_rejects_modified_version(config: AppConfig):
    crypto = CryptoManager(config)
    password = SecureString("A" * config.min_password_length)
    payload, _ = crypto.encrypt(SecureString("secret"), password)
    payload["version"] = "tampered"

    with pytest.raises(ValueError) as excinfo:
        crypto.decrypt(payload, password)

    assert "authentication error" in str(excinfo.value)


def test_decrypts_legacy_pbkdf2_payload(config: AppConfig, pbkdf2_config: AppConfig):
    password = SecureString("A" * config.min_password_length)
    legacy_crypto = CryptoManager(pbkdf2_config)
    payload, _ = legacy_crypto.encrypt(SecureString("secret"), password)

    modern_crypto = CryptoManager(config)
    decrypted = modern_crypto.decrypt(payload, password)

    assert payload["kdf"] == "pbkdf2"
    assert decrypted.get() == "secret"


def test_decrypt_accepts_legacy_json_payload(config: AppConfig):
    crypto = CryptoManager(config)
    password = SecureString("A" * config.min_password_length)
    payload_dict, payload_bytes = crypto.encrypt(SecureString("legacy"), password)

    json_payload = json.dumps(payload_dict)
    decrypted = crypto.decrypt(json_payload, password)
    assert decrypted.get() == "legacy"

    json_bytes = json_payload.encode("utf-8")
    assert not is_binary_payload(json_bytes)
    decrypted_bytes = crypto.decrypt(json_bytes, password)
    assert decrypted_bytes.get() == "legacy"


def test_mnemonic_checksum_length(config: AppConfig):
    manager = MnemonicManager(config)
    words = manager.generate()
    assert len(words.split()) == manager.default_word_count
    assert manager.validate(words)
    checksum = manager.checksum(words)
    assert len(checksum) == 6


@pytest.mark.parametrize("word_count", MnemonicManager.valid_word_counts())
def test_mnemonic_word_counts(config: AppConfig, word_count: int):
    manager = MnemonicManager(config)
    words = manager.generate(word_count)
    assert len(words.split()) == word_count
    assert manager.validate(words)


def test_invalid_mnemonic_word_count_raises(config: AppConfig):
    manager = MnemonicManager(config)
    with pytest.raises(ValueError):
        manager.generate(15)
