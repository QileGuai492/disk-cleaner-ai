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
        "C:\\Windows\\*",
        "C:\\Program Files\\*",
        "C:\\Program Files (x86)\\*",
        "C:\\ProgramData\\*",
        "C:\\$Recycle.Bin\\*",
        "C:\\System Volume Information\\*",
        "*\\$Recycle.Bin\\*",
        "*\\System Volume Information\\*",
        "*\\Microsoft\\Edge\\*",
        "*\\Google\\Chrome\\*",
        "*\\node_modules\\*",
        "*\\.git\\*",
    ])
    trusted_processes: set[str] = field(default_factory=lambda: {
        "svchost.exe", "TrustedInstaller.exe", "MsMpEng.exe",
        "System", "services.exe", "csrss.exe", "wininit.exe",
    })
    min_file_size_mb: float = 10.0
    cooldown_seconds: float = 3.0
    max_alerts_per_hour: int = 10
    detect_process: bool = True  # 是否检测关联进程（慢操作）
    max_files_per_scan: int = 10000  # 递归扫描上限，避免监控自身拖慢系统

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
        self._pending: dict[str, tuple[int, float, float, str]] = {}  # path → (size, mtime, first_seen, type)
        self._alert_count = 0
        self._alert_window_start = time.time()
        self._on_event_callback: Optional[Callable] = None
        # 冷却期很短时加快轮询，保证测试/即时监控仍能及时触发
        self._poll_interval = max(0.2, min(1.0, self.config.cooldown_seconds or 1.0))

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

    def _iter_files(self, watch_path: str):
        """递归遍历监控目录，跳过忽略目录，并限制单次扫描文件数。"""
        count = 0
        for root, dirs, files in os.walk(watch_path, followlinks=False):
            dirs[:] = [
                d for d in dirs
                if not self.config.should_ignore(os.path.join(root, d))
            ]
            for fname in files:
                path = os.path.join(root, fname)
                if self.config.should_ignore(path):
                    continue
                count += 1
                if count > self.config.max_files_per_scan:
                    return
                yield path

    def _scan_initial_state(self) -> None:
        """递归扫描监控目录的初始状态。"""
        for watch_path in self.config.watch_paths:
            if not os.path.exists(watch_path):
                continue
            try:
                for path in self._iter_files(watch_path):
                    if os.path.islink(path):
                        continue
                    try:
                        st = os.stat(path)
                        if not os.path.isfile(path):
                            continue
                        self._known_files[path] = (st.st_size, st.st_mtime)
                    except OSError:
                        pass
            except (PermissionError, OSError):
                pass

    def _monitor_loop(self) -> None:
        """监控主循环。"""
        while self._running:
            try:
                self._check_for_changes()
            except Exception:
                pass
            time.sleep(self._poll_interval)

    def _check_for_changes(self) -> None:
        """递归检查文件变更，文件写入稳定后才触发事件。"""
        min_size = int(self.config.min_file_size_mb * 1024 * 1024)
        cooldown = max(0.0, self.config.cooldown_seconds)
        now = time.time()
        seen: set[str] = set()
        complete = True

        for watch_path in self.config.watch_paths:
            if not os.path.exists(watch_path):
                continue
            count = 0
            try:
                for path in self._iter_files(watch_path):
                    count += 1
                    if count > self.config.max_files_per_scan:
                        complete = False
                        break
                    if os.path.islink(path):
                        continue
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    if not os.path.isfile(path):
                        continue

                    seen.add(path)
                    current = (st.st_size, st.st_mtime)
                    previous = self._known_files.get(path)

                    if previous is None:
                        # 新文件：先记录，等待写入稳定
                        self._known_files[path] = current
                        if st.st_size >= min_size:
                            self._pending[path] = (st.st_size, st.st_mtime, now, "created")
                        else:
                            self._pending.pop(path, None)
                        continue

                    if previous == current:
                        # 大小与 mtime 稳定，检查冷却时间
                        pending = self._pending.get(path)
                        if (
                            pending
                            and pending[0] == current[0]
                            and pending[1] == current[1]
                            and now - pending[2] >= cooldown
                        ):
                            self._maybe_emit(path, current, pending[3], now)
                        continue

                    # 文件仍在变化：保留“新文件”语义，并重置等待计时
                    self._known_files[path] = current
                    if st.st_size >= min_size:
                        pending = self._pending.get(path)
                        event_type = pending[3] if pending else "modified"
                        self._pending[path] = (st.st_size, st.st_mtime, now, event_type)
                    else:
                        self._pending.pop(path, None)
            except (PermissionError, OSError):
                continue
            if count >= self.config.max_files_per_scan:
                complete = False

        # 全量扫描完成时清理已删除文件的状态；被上限截断时不做清理
        if complete:
            for path in list(self._known_files):
                if path not in seen:
                    self._known_files.pop(path, None)
                    self._pending.pop(path, None)

    def _maybe_emit(self, path: str, current: tuple[int, float], event_type: str, now: float) -> None:
        """满足告警限制与进程过滤后发出事件。"""
        if now - self._alert_window_start > 3600:
            self._alert_count = 0
            self._alert_window_start = now

        if self._alert_count >= self.config.max_alerts_per_hour:
            return

        related_process = None
        if self.config.detect_process:
            proc_info = ProcessDetector.find_file_owner(path)
            related_process = proc_info["name"] if proc_info else None

        if related_process and self.config.is_trusted_process(related_process):
            self._pending.pop(path, None)
            return

        event = FileEvent(
            path=path,
            size=current[0],
            event_type=event_type,
            detected_at=now,
            related_process=related_process,
        )
        self._add_event(event)
        self._known_files[path] = current
        self._pending.pop(path, None)
        self._alert_count += 1

    def _add_event(self, event: FileEvent) -> None:
        """添加事件到队列"""
        with self._lock:
            self._events.append(event)
        if self._on_event_callback:
            try:
                self._on_event_callback(event)
            except Exception:
                pass
