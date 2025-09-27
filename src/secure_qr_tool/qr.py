"""QR code generation utilities."""
from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from typing import Optional

from .config import AppConfig


@dataclass(slots=True)
class QRCodeManager:
    """Generate QR codes using :mod:`segno` when available."""

    config: AppConfig

    def is_available(self) -> bool:
        try:
            import segno  # type: ignore  # pragma: no cover - optional dependency
        except Exception:
            return False
        return True

    def _ensure_bytes(self, payload: bytes | bytearray | str) -> bytes:
        """Return ``payload`` as ``bytes`` for QR operations."""

        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)
        return payload.encode("utf-8")

    def payload_digest(self, data: bytes | bytearray | str) -> str:
        """Return the SHA-256 digest of the QR payload.

        The digest allows callers to verify that a decoded payload matches the
        original data that was serialised into a QR code.  The method returns the
        digest as a hexadecimal string to avoid introducing binary data into the
        workflow.
        """

        return hashlib.sha256(self._ensure_bytes(data)).hexdigest()

    def save_png(self, data: bytes | bytearray | str, path: str) -> str:
        """Persist a QR code representing ``data`` to ``path``.

        The method returns the SHA-256 digest of ``data`` so that callers can
        display or record the checksum alongside the generated QR image.
        """

        try:
            import segno  # type: ignore  # pragma: no cover - optional dependency
        except Exception as exc:  # pragma: no cover - depends on environment
            raise RuntimeError("QR generation requires segno; install segno[pil]") from exc

        payload = self._ensure_bytes(data)
        qr = segno.make(payload, error=self.config.qr_error_correction)
        qr.save(path, scale=self.config.qr_scale, border=self.config.qr_border)

        return self.payload_digest(payload)

    def to_qpixmap(self, data: bytes | bytearray | str):  # pragma: no cover - requires PyQt at runtime
        """Return a ``QPixmap`` representing ``data``.

        The method imports :mod:`PyQt5` lazily to keep the module usable in
        headless test environments.  A :class:`RuntimeError` is raised if the
        dependency is missing.
        """

        try:
            from PyQt5.QtGui import QImage, QPixmap
        except Exception as exc:  # pragma: no cover - depends on environment
            raise RuntimeError("PyQt5 is required to generate a preview pixmap") from exc

        try:
            import segno  # type: ignore  # pragma: no cover - optional dependency
        except Exception as exc:  # pragma: no cover - depends on environment
            raise RuntimeError("QR generation requires segno; install segno[pil]") from exc

        payload = self._ensure_bytes(data)
        qr = segno.make(payload, error=self.config.qr_error_correction)
        buffer = io.BytesIO()
        qr.save(buffer, kind="png", scale=self.config.qr_scale, border=self.config.qr_border)
        buffer.seek(0)

        image = QImage()
        if not image.loadFromData(buffer.read()):
            raise RuntimeError("Failed to load QR image into QImage")

        return QPixmap.fromImage(image)

    def read_from_file(self, path: str) -> Optional[bytes]:  # pragma: no cover - requires optional deps
        """Decode QR contents using OpenCV and :mod:`pyzbar` when available."""

        try:
            import cv2  # type: ignore
            from pyzbar import pyzbar  # type: ignore
        except Exception:
            return None

        image = cv2.imread(path)
        if image is None:
            return None

        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        for processed in (
            gray,
            cv2.GaussianBlur(gray, (5, 5), 0),
            cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
        ):
            decoded = pyzbar.decode(processed)
            if decoded:
                return bytes(decoded[0].data)

        return None


__all__ = ["QRCodeManager"]
