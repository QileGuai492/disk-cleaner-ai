"""实时文件监控——检测新增文件并弹窗提醒"""

import fnmatch
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable
from typing import Optional

from disk_cleaner.monitor.process_detector import ProcessDetector


@dataclass
class FileEvent:
    """文件变更事件"""

    path: str
    size: int
    event_type: str  # created / modified
    detected_at: float = field(default_factory=time.time)
    related_process: Optional[str] = None


@dataclass
class MonitorConfig:
    """监控配置"""

    watch_paths: list[str] = field(default_factory=lambda: [
        "C:\\",
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\AppData\\Local\\Temp"),
        "C:\\Windows\\Temp",
    ])
    ignore_paths: list[str] = field(default_factory=lambda: [
        "C:\\Windows\\System32\\*",
        "C:\\Windows\\WinSxS\\*",
        "*\\Microsoft\\Edge\\*",
        "*\\Google\\Chrome\\*",
    ])
    trusted_processes: set[str] = field(default_factory=lambda: {
        "svchost.exe", "TrustedInstaller.exe", "MsMpEng.exe",
        "System", "services.exe", "csrss.exe", "wininit.exe",
    })
    min_file_size_mb: float = 10.0
    cooldown_seconds: float = 3.0
    max_alerts_per_hour: int = 10
    detect_process: bool = True  # 是否检测关联进程（慢操作）

    def should_ignore(self, path: str) -> bool:
        """检查路径是否应被忽略"""
        for pattern in self.ignore_paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def is_trusted_process(self, process_name: str) -> bool:
        """检查进程是否受信任"""
        return process_name in self.trusted_processes


class FileMonitor:
    """文件系统监控器——轮询检测新增/修改的大文件"""

    def __init__(self, config: Optional[MonitorConfig] = None):
        self.config = config or MonitorConfig()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._events: list[FileEvent] = []
        self._lock = threading.Lock()
        self._known_files: dict[str, tuple[int, float]] = {}  # path → (size, mtime)
        self._cooldowns: dict[str, float] = {}  # path → last event time
        self._alert_count = 0
        self._alert_window_start = time.time()
        self._on_event_callback: Optional[Callable] = None

    @property
    def is_running(self) -> bool:
        return self._running

    def set_callback(self, callback: Callable) -> None:
        """设置事件回调函数"""
        self._on_event_callback = callback

    def start(self) -> None:
        """启动监控"""
        if self._running:
            return
        self._running = True
        self._scan_initial_state()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """停止监控"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def get_events(self) -> list[FileEvent]:
        """获取并清空事件队列"""
        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events

    def _scan_initial_state(self) -> None:
        """扫描监控目录的初始状态"""
        for watch_path in self.config.watch_paths:
            if not os.path.exists(watch_path):
                continue
            try:
                for entry in os.scandir(watch_path):
                    if entry.is_file():
                        try:
                            stat = entry.stat()
                            self._known_files[entry.path] = (stat.st_size, stat.st_mtime)
                        except OSError:
                            pass
            except PermissionError:
                pass

    def _monitor_loop(self) -> None:
        """监控主循环"""
        while self._running:
            try:
                self._check_for_changes()
            except Exception:
                pass
            time.sleep(1.0)  # 每秒检查一次

    def _check_for_changes(self) -> None:
        """检查文件变更"""
        min_size = int(self.config.min_file_size_mb * 1024 * 1024)
        now = time.time()

        for watch_path in self.config.watch_paths:
            if not os.path.exists(watch_path):
                continue
            try:
                for entry in os.scandir(watch_path):
                    if not entry.is_file():
                        continue

                    path = entry.path

                    # 忽略系统路径
                    if self.config.should_ignore(path):
                        continue

                    try:
                        stat = entry.stat()
                    except OSError:
                        continue

                    # 大小过滤
                    if stat.st_size < min_size:
                        continue

                    # 检查是否是已知文件
                    if path in self._known_files:
                        old_size, old_mtime = self._known_files[path]
                        if stat.st_size == old_size and stat.st_mtime == old_mtime:
                            continue  # 未变化

                        # 冷却期检查
                        if path in self._cooldowns:
                            if now - self._cooldowns[path] < self.config.cooldown_seconds:
                                continue

                        event_type = "modified"
                    else:
                        event_type = "created"

                    # 速率限制
                    if now - self._alert_window_start > 3600:
                        self._alert_count = 0
                        self._alert_window_start = now

                    if self._alert_count >= self.config.max_alerts_per_hour:
                        continue

                    # 检测关联进程（可开关）
                    related_process = None
                    if self.config.detect_process:
                        proc_info = ProcessDetector.find_file_owner(path)
                        related_process = proc_info["name"] if proc_info else None

                    # 跳过受信任进程
                    if related_process and self.config.is_trusted_process(related_process):
                        continue

                    # 创建事件
                    event = FileEvent(
                        path=path,
                        size=stat.st_size,
                        event_type=event_type,
                        detected_at=now,
                        related_process=related_process,
                    )
                    self._add_event(event)
                    self._known_files[path] = (stat.st_size, stat.st_mtime)
                    self._cooldowns[path] = now
                    self._alert_count += 1

            except PermissionError:
                pass
            except OSError:
                pass

    def _add_event(self, event: FileEvent) -> None:
        """添加事件到队列"""
        with self._lock:
            self._events.append(event)
        if self._on_event_callback:
            try:
                self._on_event_callback(event)
            except Exception:
                pass
