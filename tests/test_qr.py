from __future__ import annotations

import json
import sys
import types

from secure_qr_tool.config import AppConfig
from secure_qr_tool.qr import QRCodeManager


def test_payload_digest_matches_sha256():
    manager = QRCodeManager(AppConfig())
    payload = json.dumps({"salt": "abc", "nonce": "def"}).encode("utf-8")

    digest = manager.payload_digest(payload)

    assert digest == manager.payload_digest(payload)
    assert len(digest) == 64


def test_payload_digest_accepts_text():
    manager = QRCodeManager(AppConfig())
    payload = json.dumps({"ciphertext": "value"})

    digest_from_text = manager.payload_digest(payload)
    digest_from_bytes = manager.payload_digest(payload.encode("utf-8"))

    assert digest_from_text == digest_from_bytes


def test_save_png_returns_digest(monkeypatch, tmp_path):
    """``save_png`` should return the digest even when segno is mocked."""

    class DummyQR:
        def save(self, *_args, **_kwargs):
            return None

    def fake_make(_data, **_kwargs):
        return DummyQR()

    module = types.SimpleNamespace(make=fake_make)
    monkeypatch.setitem(sys.modules, "segno", module)

    manager = QRCodeManager(AppConfig())
    data = b"payload"
    digest = manager.save_png(data, str(tmp_path / "qr.png"))

    assert digest == manager.payload_digest(data)
