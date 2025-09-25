"""Secure QR Code Tool package."""
from __future__ import annotations

from .config import AppConfig, CameraConfig, StyleConfig
from .network import is_online
from .qr import QRCodeManager
from .security import CryptoManager, MnemonicManager, SecureString
from .state import AppState

__all__ = [
    "AppConfig",
    "CameraConfig",
    "StyleConfig",
    "AppState",
    "is_online",
    "QRCodeManager",
    "CryptoManager",
    "MnemonicManager",
    "SecureString",
]

__version__ = "3.0"
