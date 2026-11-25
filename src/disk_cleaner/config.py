"""统一配置——~/.disk-cleaner/config.json。

所有可调参数集中在这里，避免模型名、备份路径、端口散落在 CLI/GUI/引擎中。
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """配置文件格式错误。"""


def get_config_path(path: str | None = None) -> Path:
    configured = path or os.environ.get("DISK_CLEANER_CONFIG")
    if configured:
        return Path(configured).expanduser()
    return Path(os.path.expanduser("~/.disk-cleaner/config.json"))


@dataclass
class BackupSettings:
    dir: str = "~/disk-cleaner-backup"
    retention_days: int = 30


@dataclass
class ScanSettings:
    max_dirs: int = 5000
    skip_symlinks: bool = True


@dataclass
class AISettings:
    provider: str = "local"
    model: str = ""
    max_retries: int = 3
    rate_limit_rpm: int = 30
    cloud_blocklist: list[str] = field(default_factory=list)


@dataclass
class PrivacySettings:
    level: str = "strict"
    extension_blocklist: list[str] = field(default_factory=lambda: [
        ".env", ".pem", ".key", ".pfx", ".p12", ".kdbx", ".enc",
    ])


@dataclass
class GuiSettings:
    port: int = 8765
    open_browser: bool = True


@dataclass
class MonitorSettings:
    min_file_size_mb: float = 10.0
    cooldown_seconds: float = 3.0
    max_alerts_per_hour: int = 10
    max_files_per_scan: int = 10000


@dataclass
class LogSettings:
    level: str = "INFO"


@dataclass
class AppConfig:
    data_dir: str = "~/.disk-cleaner"
    backup: BackupSettings = field(default_factory=BackupSettings)
    scan: ScanSettings = field(default_factory=ScanSettings)
    ai: AISettings = field(default_factory=AISettings)
    privacy: PrivacySettings = field(default_factory=PrivacySettings)
    gui: GuiSettings = field(default_factory=GuiSettings)
    monitor: MonitorSettings = field(default_factory=MonitorSettings)
    log: LogSettings = field(default_factory=LogSettings)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "AppConfig":
        data = data if isinstance(data, dict) else {}
        return cls(
            data_dir=_as_str(data.get("data_dir"), "~/.disk-cleaner"),
            backup=_section(BackupSettings, data.get("backup")),
            scan=_section(ScanSettings, data.get("scan")),
            ai=_section(AISettings, data.get("ai")),
            privacy=_section(PrivacySettings, data.get("privacy")),
            gui=_section(GuiSettings, data.get("gui")),
            monitor=_section(MonitorSettings, data.get("monitor")),
            log=_section(LogSettings, data.get("log")),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _as_str(value: Any, default: str) -> str:
    return value if isinstance(value, str) and value.strip() else default


def _section(cls, raw: Any):
    """按 dataclass 字段类型解析一个配置段，未知字段忽略。"""
    if not isinstance(raw, dict):
        return cls()
    default_obj = cls()
    kwargs: dict[str, Any] = {}
    for item in fields(cls):
        if item.name not in raw:
            continue
        value = raw[item.name]
        default = getattr(default_obj, item.name)
        if is_dataclass(default):
            kwargs[item.name] = _section(type(default), value)
        elif isinstance(default, bool):
            if isinstance(value, bool):
                kwargs[item.name] = value
        elif isinstance(default, int):
            try:
                kwargs[item.name] = int(value)
            except (TypeError, ValueError):
                pass
        elif isinstance(default, float):
            try:
                kwargs[item.name] = float(value)
            except (TypeError, ValueError):
                pass
        elif isinstance(default, list):
            if isinstance(value, list):
                kwargs[item.name] = [str(v) for v in value]
        elif isinstance(default, str):
            if isinstance(value, str):
                kwargs[item.name] = value
    return cls(**kwargs)


def load_config(path: str | None = None) -> AppConfig:
    config_path = get_config_path(path)
    if not config_path.exists():
        return AppConfig()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"无法读取配置文件 {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"配置文件顶层必须是对象: {config_path}")
    return AppConfig.from_dict(raw)


def save_config(config: AppConfig, path: str | None = None) -> Path:
    config_path = get_config_path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps(config.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return config_path


def ensure_default_config(path: str | None = None, force: bool = False) -> Path:
    config_path = get_config_path(path)
    if force or not config_path.exists():
        save_config(AppConfig(), config_path)
    return config_path
