"""日志与审计——文件日志 + 本地 JSONL 审计记录。"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

_AUDIT_PATH: Path | None = None
_AUDIT_LOCK = threading.Lock()
_LOGGER_NAME = "disk_cleaner"


def setup_logging(level: str | None = None, log_dir: str | None = None) -> logging.Logger:
    """初始化文件日志；重复调用不会重复添加 handler。"""
    global _AUDIT_PATH

    if level is None:
        try:
            from disk_cleaner.config import load_config
            level = load_config().log.level
        except Exception:
            level = "INFO"

    base = Path(log_dir).expanduser() if log_dir else Path(
        os.path.expanduser("~/.disk-cleaner/logs")
    )
    base.mkdir(parents=True, exist_ok=True)
    _AUDIT_PATH = base / "audit.jsonl"

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.propagate = False

    already = any(
        isinstance(handler, RotatingFileHandler)
        and getattr(handler, "baseFilename", "").endswith("disk-cleaner.log")
        for handler in logger.handlers
    )
    if not already:
        handler = RotatingFileHandler(
            base / "disk-cleaner.log",
            maxBytes=2 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        ))
        logger.addHandler(handler)
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME + (f".{name}" if name else ""))


def audit(event: str, **fields) -> None:
    """追加一条审计记录；未调用 setup_logging 时静默跳过。"""
    if _AUDIT_PATH is None:
        return
    record = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "event": event,
    }
    record.update(fields)
    try:
        with _AUDIT_LOCK:
            with open(_AUDIT_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass
