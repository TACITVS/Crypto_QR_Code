"""Security primitives used by the Secure QR Code Tool."""
from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, Mapping, Tuple

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from mnemonic import Mnemonic

from .config import AppConfig
from .payload import decode_payload, encode_components, is_binary_payload


class SecureString:
    """A mutable bytearray backed string that can be wiped from memory."""

    __slots__ = ("_data",)

    def __init__(self, data: bytes | str):
        if isinstance(data, bytes):
            self._data = bytearray(data)
        else:
            self._data = bytearray(data.encode("utf-8"))

    def get(self) -> str:
        """Return the string representation using UTF-8 decoding."""

        return self._data.decode("utf-8")

    def get_bytes(self) -> bytes:
        """Return a ``bytes`` view of the stored data."""

        return bytes(self._data)

    def copy(self) -> "SecureString":
        """Return a copy that owns its own backing buffer."""

        return SecureString(self.get_bytes())

    def clear(self) -> None:
        """Overwrite the backing buffer with zeros."""

        for index in range(len(self._data)):
            self._data[index] = 0
        self._data = bytearray()

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._data)

    def __enter__(self) -> "SecureString":  # pragma: no cover - trivial
        return self

    def __exit__(self, *_exc_info: object) -> None:  # pragma: no cover - trivial
        self.clear()

    def __del__(self):  # pragma: no cover - best effort cleanup
        try:
            self.clear()
        except Exception:
            pass


@dataclass(slots=True)
class CryptoManager:
    """High level facade around encryption primitives."""

    config: AppConfig

    _SUPPORTED_KDFS = ("argon2id", "pbkdf2")

    def _normalise_kdf_name(self, name: str | None) -> str:
        algorithm = (name or self.config.kdf_algorithm).strip().lower()
        if algorithm not in self._SUPPORTED_KDFS:
            raise ValueError(f"Unsupported KDF algorithm: {name}")
        return algorithm

    def _derive_key_pbkdf2(self, password: SecureString, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.config.aes_key_size_bytes,
            salt=salt,
            iterations=self.config.pbkdf2_iterations,
            backend=default_backend(),
        )
        return kdf.derive(password.get_bytes())

    def _derive_key_argon2(self, password: SecureString, salt: bytes) -> bytes:
        return hash_secret_raw(
            password.get_bytes(),
            salt,
            time_cost=self.config.argon2_time_cost,
            memory_cost=self.config.argon2_memory_cost_kib,
            parallelism=self.config.argon2_parallelism,
            hash_len=self.config.aes_key_size_bytes,
            type=Argon2Type.ID,
        )

    def _derive_key(
        self, password: SecureString, salt: bytes, algorithm: str | None = None
    ) -> bytes:
        alg = self._normalise_kdf_name(algorithm)
        if alg == "argon2id":
            return self._derive_key_argon2(password, salt)
        if alg == "pbkdf2":
            return self._derive_key_pbkdf2(password, salt)
        raise ValueError(f"Unsupported KDF algorithm: {alg}")

    @staticmethod
    def _build_aad(version: str, kdf_algorithm: str) -> bytes:
        metadata = {
            "cipher": "AES-256-GCM",
            "kdf": kdf_algorithm,
            "version": version,
        }
        return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    @staticmethod
    def _dedupe_preserve_order(items: Iterable[str]) -> tuple[str, ...]:
        seen: Dict[str, None] = {}
        for item in items:
            if item not in seen:
                seen[item] = None
        return tuple(seen)

    def encrypt(
        self, data: SecureString, password: SecureString
    ) -> Tuple[Dict[str, str], bytes]:
        """Encrypt ``data`` using AES-256-GCM.

        The method returns a tuple ``(payload_dict, payload_bytes)`` where the
        first item is a JSON serialisable dictionary containing the salt, nonce
        and ciphertext encoded in base64, and the second item is the compact
        binary representation suitable for QR encoding.
        """

        salt = os.urandom(self.config.salt_size_bytes)
        kdf_algorithm = self._normalise_kdf_name(None)
        key = self._derive_key(password, salt, kdf_algorithm)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        version = self.config.app_version
        aad = self._build_aad(version, kdf_algorithm)
        ciphertext = aesgcm.encrypt(nonce, data.get_bytes(), aad)

        payload = {
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "version": version,
            "kdf": kdf_algorithm,
        }

        binary = encode_components(
            version=version,
            kdf=kdf_algorithm,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
        )

        return payload, binary

    def decrypt(
        self,
        payload: Dict[str, str] | Mapping[str, str] | bytes | str,
        password: SecureString,
    ) -> SecureString:
        """Decrypt the dictionary generated by :meth:`encrypt`."""

        payload_dict: Dict[str, str]
        if isinstance(payload, bytes):
            if is_binary_payload(payload):
                payload_dict = decode_payload(payload)
            else:
                try:
                    payload_dict = json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError("Invalid payload format") from exc
        elif isinstance(payload, str):
            try:
                payload_dict = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid payload format") from exc
        elif isinstance(payload, Mapping):
            payload_dict = dict(payload)
        else:  # pragma: no cover - defensive
            raise ValueError("Unsupported payload type")

        required = {"salt", "nonce", "ciphertext"}
        missing = required.difference(payload_dict)
        if missing:
            raise ValueError(f"Invalid payload, missing fields: {sorted(missing)}")

        try:
            salt = base64.b64decode(payload_dict["salt"])
            nonce = base64.b64decode(payload_dict["nonce"])
            ciphertext = base64.b64decode(payload_dict["ciphertext"])
        except (TypeError, binascii.Error) as exc:
            raise ValueError("Payload contains invalid base64 data") from exc

        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes for AES-GCM")

        version = payload_dict.get("version", self.config.app_version)
        preferred_algorithm = payload_dict.get("kdf")
        candidates = []
        if preferred_algorithm is not None:
            candidates.append(self._normalise_kdf_name(preferred_algorithm))
        else:
            candidates.append(self._normalise_kdf_name(None))
            if self.config.kdf_algorithm.lower() != "pbkdf2":
                candidates.append("pbkdf2")

        last_error: Exception | None = None
        for algorithm in self._dedupe_preserve_order(candidates):
            key = self._derive_key(password, salt, algorithm)
            aesgcm = AESGCM(key)
            aad = self._build_aad(version, algorithm)
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            except InvalidTag as exc:
                last_error = exc
                continue
            except ValueError as exc:
                raise ValueError(f"Decryption failed: {exc}") from exc
            except Exception as exc:  # pragma: no cover - defensive
                raise ValueError("Decryption failed") from exc
            return SecureString(plaintext)

        raise ValueError("Decryption failed: authentication error") from last_error


@dataclass(slots=True)
class MnemonicManager:
    """Utility wrapper around the ``mnemonic`` package."""

    _WORD_COUNT_TO_STRENGTH = {12: 128, 18: 192, 24: 256}

    config: AppConfig
    _mnemonic: Mnemonic = field(init=False, repr=False)
    _default_word_count: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_mnemonic", Mnemonic("english"))
        default = getattr(self.config, "mnemonic_default_words", 24)
        if default not in self._WORD_COUNT_TO_STRENGTH:
            raise ValueError(
                "mnemonic_default_words must be one of: "
                f"{sorted(self._WORD_COUNT_TO_STRENGTH)}"
            )
        object.__setattr__(self, "_default_word_count", default)

    @property
    def default_word_count(self) -> int:
        return self._default_word_count

    @classmethod
    def valid_word_counts(cls) -> tuple[int, ...]:
        return tuple(sorted(cls._WORD_COUNT_TO_STRENGTH))

    def generate(self, word_count: int | None = None) -> str:
        if word_count is None:
            word_count = self._default_word_count
        try:
            strength = self._WORD_COUNT_TO_STRENGTH[word_count]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(
                "word_count must be one of: "
                f"{sorted(self._WORD_COUNT_TO_STRENGTH)}"
            ) from exc
        return self._mnemonic.generate(strength=strength)

    def validate(self, mnemonic: str) -> bool:
        return self._mnemonic.check(mnemonic)

    @staticmethod
    def checksum(mnemonic: str) -> str:
        import hashlib

        return hashlib.sha256(mnemonic.encode("utf-8")).hexdigest()[:6].upper()


__all__ = ["SecureString", "CryptoManager", "MnemonicManager"]
