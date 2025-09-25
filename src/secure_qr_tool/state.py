"""Runtime state containers used by the Secure QR Code Tool."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass(slots=True)
class AppState:
    """Mutable state shared between UI components."""

    master_password: Optional["SecureString"] = None
    current_encrypted_payload: Optional[Dict[str, str]] = None
    is_online: bool = False
    camera_available: bool = False
    qr_available: bool = False


# The SecureString type is defined in ``security`` but importing it at module
# level would pull in the cryptography dependency for consumers that only wish
# to read configuration data.  We therefore use a ``TYPE_CHECKING`` guard to
# avoid circular imports while still providing type information for tooling.
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for static type checking only
    from .security import SecureString


__all__ = ["AppState"]
