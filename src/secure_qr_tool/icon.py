"""Application icon helpers."""
from __future__ import annotations


def create_icon(size: int = 64):  # pragma: no cover - requires PyQt at runtime
    """Create a :class:`~PyQt5.QtGui.QIcon` used by the GUI.

    The import is performed lazily so that automated tests do not require a
    graphical backend.
    """

    try:
        from PyQt5.QtGui import QColor, QFont, QIcon, QPainter, QPen, QPixmap, QBrush
        from PyQt5.QtCore import Qt
    except Exception as exc:  # pragma: no cover - depends on environment
        raise RuntimeError("PyQt5 is required to generate the application icon") from exc

    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QBrush(QColor("#88C0D0")))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(4, 4, size - 8, size - 8)

    painter.setPen(QPen(Qt.white, 2))
    painter.setFont(QFont("Arial", size // 3, QFont.Bold))
    painter.drawText(pixmap.rect(), Qt.AlignCenter, "Q")
    painter.end()

    return QIcon(pixmap)


__all__ = ["create_icon"]
