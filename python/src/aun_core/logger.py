from __future__ import annotations

import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def _log_dir() -> Path:
    return Path.home() / ".aun" / "logs"


def _log_path(date_str: str) -> Path:
    return _log_dir() / f"python-sdk-{date_str}.log"


def _cleanup_old_logs(keep_days: int = 3) -> None:
    log_dir = _log_dir()
    if not log_dir.exists():
        return
    cutoff = time.time() - keep_days * 86400
    for f in log_dir.glob("python-sdk-*.log"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
        except OSError:
            pass


if sys.platform == "win32":
    import msvcrt

    def _write_locked(path: Path, line: str) -> None:
        with open(path, "ab") as f:
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            try:
                f.write(line.encode("utf-8"))
            finally:
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
else:
    import fcntl

    def _write_locked(path: Path, line: str) -> None:
        with open(path, "a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(line)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)


class AUNLogger:
    """多进程安全的 AUN SDK 调试日志记录器。"""

    def __init__(self, aid: str | None = None) -> None:
        self._aid = aid or ""
        _log_dir().mkdir(parents=True, exist_ok=True)
        _cleanup_old_logs()

    def set_aid(self, aid: str) -> None:
        self._aid = f" [{aid}]" if aid else ""

    def log(self, message: str) -> None:
        now = datetime.now(timezone.utc)
        ts_fmt = now.strftime("%H:%M:%S") + f".{now.microsecond // 1000:03d}"
        line = f"{ts_fmt}{self._aid} {message}\n"
        path = _log_path(now.strftime("%Y%m%d"))
        try:
            _write_locked(path, line)
        except OSError as exc:
            print(f"[AUNLogger] 写日志文件失败: {exc}", file=sys.stderr)


class AUNLogHandler(logging.Handler):
    """将 logging 日志转发到 AUNLogger 文件的 Handler（日志 hook）。
    注入到 getLogger("aun_core") 后，所有标准日志自动双写到文件。"""

    def __init__(self, logger: AUNLogger) -> None:
        super().__init__()
        self._logger = logger

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._logger.log(msg)
        except Exception:
            self.handleError(record)
