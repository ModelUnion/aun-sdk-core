"""AUN SDK 日志模块 — 统一格式、控制台/文件双路由、log.ini 全局配置。"""

from __future__ import annotations

import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

_LEVEL_ORDER = {"debug": 0, "info": 1, "warn": 2, "error": 3}
_GLOBAL_INI_PATH = Path.home() / ".aun" / "log.ini"


def _parse_log_ini(path: Path) -> dict[str, str]:
    """解析 ~/.aun/log.ini，返回 key=value 字典。"""
    result: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.strip().lower()] = value.strip().lower()
    except OSError:
        pass
    return result


def _parse_bool(value: str) -> bool:
    return value in ("1", "true", "on")


class AUNLogger:
    """AUN SDK 统一日志记录器。

    格式: [yyyy-mm-dd HH:mm:ss.SSS][LEVEL][module] message

    优先级:
      1. ~/.aun/log.ini 存在 → 使用文件配置，日志目录强制 ~/.aun/logs/
      2. 不存在 → 使用代码传入的 debug 参数，日志目录为 {aun_path}/logs/
    """

    def __init__(self, debug: bool = False, aun_path: str | None = None) -> None:
        ini = _parse_log_ini(_GLOBAL_INI_PATH) if _GLOBAL_INI_PATH.exists() else {}

        if ini:
            self._debug = _parse_bool(ini.get("debug", "off"))
            self._log_dir = Path.home() / ".aun" / "logs"
            level_str = ini.get("level", "debug" if self._debug else "info")
        else:
            self._debug = debug
            self._log_dir = (Path(aun_path) if aun_path else Path.home() / ".aun") / "logs"
            level_str = "debug" if self._debug else "info"

        self._min_level = _LEVEL_ORDER.get(level_str, 1)

        if self._debug:
            self._log_dir.mkdir(parents=True, exist_ok=True)
            self._cleanup_old_logs()

    # ------ 公开接口 ------

    def error(self, module: str, msg: str, *args: object, err: BaseException | None = None) -> None:
        if self._min_level > _LEVEL_ORDER["error"]:
            return
        line = self._format("ERROR", module, msg, args)
        self._console(line)
        if self._debug:
            self._file(line, err)

    def warn(self, module: str, msg: str, *args: object) -> None:
        if self._min_level > _LEVEL_ORDER["warn"]:
            return
        line = self._format("WARN", module, msg, args)
        self._console(line)
        if self._debug:
            self._file(line)

    def info(self, module: str, msg: str, *args: object) -> None:
        if self._min_level > _LEVEL_ORDER["info"]:
            return
        line = self._format("INFO", module, msg, args)
        self._console(line)
        if self._debug:
            self._file(line)

    def debug(self, module: str, msg: str, *args: object) -> None:
        if not self._debug or self._min_level > _LEVEL_ORDER["debug"]:
            return
        line = self._format("DEBUG", module, msg, args)
        self._console(line)
        self._file(line)

    # ------ 内部实现 ------

    def _format(self, level: str, module: str, msg: str, args: tuple) -> str:
        now = datetime.now()
        ts = now.strftime("%Y-%m-%d %H:%M:%S") + f".{now.microsecond // 1000:03d}"
        text = msg % args if args else msg
        return f"[{ts}][{level}][{module}] {text}"

    def _console(self, line: str) -> None:
        # 直接写 UTF-8 字节，绕开 sys.stderr.encoding（Windows 默认 cp936 会对 emoji/生僻字报错）
        data = (line + "\n").encode("utf-8", errors="replace")
        try:
            sys.stderr.buffer.write(data)
            sys.stderr.flush()
        except (AttributeError, OSError):
            # stderr 被替换为无 buffer 对象（pytest capsys / StringIO 等）时降级
            print(line, file=sys.stderr, flush=True)

    def _file(self, line: str, err: BaseException | None = None) -> None:
        today = datetime.now().strftime("%Y-%m-%d")
        path = self._log_dir / f"python-sdk-{today}.log"
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                if err is not None:
                    tb = "".join(traceback.format_exception(type(err), err, err.__traceback__))
                    f.write(tb)
        except OSError:
            pass

    def _cleanup_old_logs(self) -> None:
        cutoff = time.time() - 7 * 86400
        for f in self._log_dir.glob("python-sdk-*.log"):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink(missing_ok=True)
            except OSError:
                pass


class NullLogger:
    """静默 logger，用于不需要日志输出的场景。"""

    def error(self, module: str, msg: str, *args: object, err: BaseException | None = None) -> None:
        pass

    def warn(self, module: str, msg: str, *args: object) -> None:
        pass

    def info(self, module: str, msg: str, *args: object) -> None:
        pass

    def debug(self, module: str, msg: str, *args: object) -> None:
        pass
