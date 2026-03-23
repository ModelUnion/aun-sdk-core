from __future__ import annotations

import sys

from .base import SecretStore
from .dpapi import DPAPISecretStore
from .volatile import VolatileSecretStore


def create_default_secret_store() -> SecretStore:
    if sys.platform == "win32" and DPAPISecretStore.is_supported():
        return DPAPISecretStore()
    return VolatileSecretStore()
