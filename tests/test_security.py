from __future__ import annotations

import base64

import pytest

from secure_qr_tool.config import AppConfig
from secure_qr_tool.security import CryptoManager, MnemonicManager, SecureString


@pytest.fixture()
def config() -> AppConfig:
    return AppConfig(pbkdf2_iterations=10_000)


def test_secure_string_clears_buffer():
    secret = SecureString("top secret")
    assert secret.get() == "top secret"
    secret.clear()
    assert secret.get() == ""


def test_encrypt_roundtrip(config: AppConfig):
    crypto = CryptoManager(config)
    password = SecureString("A" * config.min_password_length)
    payload = crypto.encrypt(SecureString("mnemonic words"), password)
    assert set(payload) == {"salt", "nonce", "ciphertext", "version"}

    decrypted = crypto.decrypt(payload, password)
    assert decrypted.get() == "mnemonic words"


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
    payload = crypto.encrypt(SecureString("secret"), password)

    wrong_password = SecureString("B" * config.min_password_length)
    with pytest.raises(ValueError) as excinfo:
        crypto.decrypt(payload, wrong_password)

    assert "authentication error" in str(excinfo.value)


def test_decrypt_with_invalid_nonce_length(config: AppConfig):
    crypto = CryptoManager(config)
    password = SecureString("A" * config.min_password_length)
    payload = crypto.encrypt(SecureString("secret"), password)
    payload["nonce"] = base64.b64encode(b"short").decode("ascii")

    with pytest.raises(ValueError) as excinfo:
        crypto.decrypt(payload, password)

    assert "Nonce" in str(excinfo.value) or "between" in str(excinfo.value)


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
