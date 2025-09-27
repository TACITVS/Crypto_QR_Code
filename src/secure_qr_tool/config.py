"""Configuration data structures for the Secure QR Code Tool."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(slots=True)
class AppConfig:
    """Static configuration options used across the application."""

    app_name: str = "SecureQRCodeTool"
    app_version: str = "3.0"
    repo_url: str = "https://github.com/TACITVS/Crypto_QR_Code"
    min_password_length: int = 12
    kdf_algorithm: str = "argon2id"
    pbkdf2_iterations: int = 600_000
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 131_072
    argon2_parallelism: int = 2
    salt_size_bytes: int = 16
    aes_key_size_bytes: int = 32
    mnemonic_default_words: int = 24
    network_check_interval_ms: int = 5_000
    camera_frame_skip: int = 5
    qr_error_correction: str = "M"
    qr_scale: int = 10
    qr_border: int = 4
    max_frame_size: int = 1_920


@dataclass(slots=True)
class CameraConfig:
    """Runtime camera configuration used by the optional camera worker."""

    width: int = 640
    height: int = 480

    def get_backends(self) -> List[int]:
        """Return a list of OpenCV backend identifiers to try.

        OpenCV is optional.  The function therefore performs the imports lazily
        so that unit tests can run in environments without the optional
        dependencies installed.
        """

        try:  # pragma: no cover - imported for type side effect only
            import cv2  # type: ignore
        except Exception:  # pragma: no cover - we simply fall back to an empty list
            return []

        try:
            return [cv2.CAP_DSHOW, cv2.CAP_MSMF, cv2.CAP_ANY]
        except AttributeError:  # pragma: no cover - depends on the OpenCV build
            return [0]

    def get_indices(self) -> List[int]:
        """Return candidate camera indices."""

        return [0, 1, 2]


@dataclass(slots=True)
class StyleConfig:
    """Simple grouping of UI styling constants."""

    bg_primary: str = "#2E3440"
    bg_secondary: str = "#3B4252"
    bg_tertiary: str = "#434C5E"
    fg_primary: str = "#D8DEE9"
    fg_secondary: str = "#ECEFF4"
    accent_primary: str = "#88C0D0"
    accent_secondary: str = "#5E81AC"
    warning: str = "#BF616A"
    success: str = "#A3BE8C"
    border: str = "#4C566A"
    font_family: str = "Segoe UI, sans-serif"
    font_size: int = 14
    font_mono: str = "Courier New, monospace"


__all__ = ["AppConfig", "CameraConfig", "StyleConfig"]
