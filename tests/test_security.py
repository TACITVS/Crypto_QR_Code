from __future__ import annotations

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


def test_mnemonic_checksum_length(config: AppConfig):
    manager = MnemonicManager(config)
    words = manager.generate()
    assert manager.validate(words)
    checksum = manager.checksum(words)
    assert len(checksum) == 6
