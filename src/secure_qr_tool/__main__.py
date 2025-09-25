"""Run the Secure QR Code Tool GUI."""
from __future__ import annotations

from .app import run


def main() -> int:
    return run()


if __name__ == "__main__":  # pragma: no cover - manual launch only
    raise SystemExit(main())
