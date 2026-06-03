from __future__ import annotations

from typing import Any


class ClientRuntime:
    """AUNClient 共享运行时占位组件。"""

    def __init__(self, client: Any) -> None:
        self.client = client
