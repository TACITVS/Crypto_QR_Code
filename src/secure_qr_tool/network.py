"""Network utility helpers."""
from __future__ import annotations

import socket


def is_online(timeout: float = 1.0) -> bool:
    """Return ``True`` if the environment can reach a public DNS server."""

    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock.connect_ex(("1.1.1.1", 53)) == 0
    except OSError:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


__all__ = ["is_online"]
