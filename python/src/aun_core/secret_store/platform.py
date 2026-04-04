from __future__ import annotations

import logging
import sys

from .base import SecretStore
from .volatile import VolatileSecretStore

_log = logging.getLogger(__name__)


def create_default_secret_store() -> SecretStore:
    if sys.platform == "win32":
        from .dpapi import DPAPISecretStore

        if DPAPISecretStore.is_supported():
            return DPAPISecretStore()

    elif sys.platform == "darwin":
        from .keychain import KeychainSecretStore

        if KeychainSecretStore.is_supported():
            return KeychainSecretStore()

    elif sys.platform.startswith("linux"):
        from .libsecret import LibsecretSecretStore

        if LibsecretSecretStore.is_supported():
            return LibsecretSecretStore()

    _log.warning(
        "平台原生密钥存储不可用，降级到 VolatileSecretStore（纯内存）。"
        "私钥在进程重启后将丢失。生产环境请确保平台密钥存储可用。"
    )
    return VolatileSecretStore()
