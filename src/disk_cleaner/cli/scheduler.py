"""定时扫描调度器"""

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional


@dataclass
class ScheduleConfig:
    """调度配置"""

    scan_paths: list[str] = field(default_factory=lambda: ["C:\\Users"])
    interval_hours: float = 24.0  # 扫描间隔
    auto_clean: bool = False  # 是否自动清理（仅 safe_to_delete）
    notify_on_findings: bool = True  # 发现可清理文件时通知
    enabled: bool = True


class ScanScheduler:
    """定时扫描调度器"""

    def __init__(self, config_path: str = "~/.disk-cleaner/schedule.json"):
        self.config_path = os.path.expanduser(config_path)
        base = os.path.dirname(self.config_path)
        self.pid_path = os.path.join(base, "scheduler.pid")
        self.state_path = os.path.join(base, "schedule_state.json")
        self.config = self._load_config()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._last_scan: Optional[datetime] = None
        self._next_scan: Optional[datetime] = None
        self._load_state()
        self._on_scan_complete: Optional[Callable] = None
        self._scan_function: Optional[Callable] = None

    def _load_config(self) -> ScheduleConfig:
        """加载调度配置"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, encoding="utf-8-sig") as f:
                    data = json.load(f)
                return ScheduleConfig(**data)
            except Exception:
                pass
        return ScheduleConfig()

    def _save_config(self) -> None:
        """保存调度配置"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "scan_paths": self.config.scan_paths,
                    "interval_hours": self.config.interval_hours,
                    "auto_clean": self.config.auto_clean,
                    "notify_on_findings": self.config.notify_on_findings,
                    "enabled": self.config.enabled,
                },
                f, ensure_ascii=False, indent=2,
            )

    def _load_state(self) -> None:
        if not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, encoding="utf-8-sig") as f:
                data = json.load(f)
            if data.get("last_scan"):
                self._last_scan = datetime.fromisoformat(data["last_scan"])
            if data.get("next_scan"):
                self._next_scan = datetime.fromisoformat(data["next_scan"])
        except Exception:
            pass

    def _save_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump({
                    "last_scan": self._last_scan.isoformat() if self._last_scan else None,
                    "next_scan": self._next_scan.isoformat() if self._next_scan else None,
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def read_pid(self) -> Optional[int]:
        try:
            with open(self.pid_path, encoding="utf-8") as f:
                return int(f.read().strip())
        except Exception:
            return None

    def write_pid(self, pid: int | None = None) -> None:
        os.makedirs(os.path.dirname(self.pid_path), exist_ok=True)
        with open(self.pid_path, "w", encoding="utf-8") as f:
            f.write(str(pid or os.getpid()))

    def remove_pid(self) -> None:
        try:
            os.remove(self.pid_path)
        except OSError:
            pass

    def is_daemon_running(self) -> bool:
        pid = self.read_pid()
        if not pid:
            return False
        try:
            import psutil
            return psutil.pid_exists(pid)
        except Exception:
            return False

    def set_scan_function(self, func: Callable) -> None:
        """设置扫描回调函数"""
        self._scan_function = func

    def set_on_complete(self, callback: Callable) -> None:
        """设置扫描完成回调"""
        self._on_scan_complete = callback

    def start(self) -> None:
        """启动调度器"""
        if self._running:
            return

        if not self.config.enabled:
            return

        self._running = True
        self._next_scan = datetime.now()  # 立即执行第一次
        self._thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """停止调度器"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def status(self) -> dict:
        return {
            "running": self._running,
            "last_scan": self._last_scan.isoformat() if self._last_scan else None,
            "next_scan": self._next_scan.isoformat() if self._next_scan else None,
            "config": {
                "scan_paths": self.config.scan_paths,
                "interval_hours": self.config.interval_hours,
                "auto_clean": self.config.auto_clean,
            },
        }

    def run_now(self) -> None:
        """立即执行一次扫描"""
        self._next_scan = datetime.now()

    def run_once(self) -> None:
        """同步执行一次扫描（供 `schedule run` 使用）。"""
        self._do_scan()
        now = datetime.now()
        self._last_scan = now
        self._next_scan = now + timedelta(hours=self.config.interval_hours)
        self._save_state()

    def _scheduler_loop(self) -> None:
        """调度主循环"""
        while self._running:
            now = datetime.now()
            if self._next_scan and now >= self._next_scan:
                self._do_scan()
                self._last_scan = now
                self._next_scan = now + timedelta(hours=self.config.interval_hours)
                self._save_state()
            time.sleep(30)  # 每 30 秒检查一次

    def _do_scan(self) -> None:
        """执行扫描"""
        if self._scan_function:
            try:
                for path in self.config.scan_paths:
                    if os.path.exists(path):
                        self._scan_function(path)
            except Exception:
                pass

        if self._on_scan_complete:
            try:
                self._on_scan_complete()
            except Exception:
                pass
