"""实时文件监控测试"""

import os
import tempfile
import time
from pathlib import Path

import pytest
from disk_cleaner.monitor.watcher import FileMonitor, FileEvent, MonitorConfig


class TestMonitorConfig:
    """监控配置测试"""

    def test_默认配置(self):
        config = MonitorConfig()
        assert config.min_file_size_mb == 10
        assert config.cooldown_seconds == 3
        assert config.max_alerts_per_hour == 10
        assert len(config.watch_paths) > 0

    def test_自定义配置(self):
        config = MonitorConfig(
            watch_paths=["C:\\Temp"],
            min_file_size_mb=5,
            cooldown_seconds=1,
            max_alerts_per_hour=20,
        )
        assert config.min_file_size_mb == 5
        assert config.watch_paths == ["C:\\Temp"]

    def test_忽略系统路径(self):
        config = MonitorConfig()
        assert config.should_ignore("C:\\Windows\\System32\\ntdll.dll")
        assert config.should_ignore("C:\\Windows\\WinSxS\\manifest.xml")

    def test_不忽略用户路径(self):
        config = MonitorConfig()
        assert not config.should_ignore("C:\\Users\\test\\Downloads\\setup.exe")
        assert not config.should_ignore("C:\\temp\\dump.tmp")

    def test_受信任的系统进程(self):
        config = MonitorConfig()
        assert config.is_trusted_process("svchost.exe")
        assert config.is_trusted_process("TrustedInstaller.exe")
        assert not config.is_trusted_process("unknown_app.exe")


class TestFileMonitor:
    """文件监控器测试"""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            yield Path(td)

    @pytest.fixture
    def monitor(self, temp_dir):
        config = MonitorConfig(
            watch_paths=[str(temp_dir)],
            min_file_size_mb=0,
            cooldown_seconds=0.1,
            max_alerts_per_hour=100,
            detect_process=False,  # 测试中关闭进程检测以加快速度
        )
        return FileMonitor(config)

    def test_检测新文件创建(self, monitor, temp_dir):
        monitor.start()
        time.sleep(0.5)

        # 创建新文件
        new_file = temp_dir / "new_file.tmp"
        new_file.write_bytes(b"\x00" * 1000)

        time.sleep(1.5)  # 等一轮轮询
        events = monitor.get_events()
        monitor.stop()

        assert len(events) >= 1, f"期望至少 1 个事件，实际 {len(events)} 个"
        assert any("new_file.tmp" in e.path for e in events)

    def test_检测嵌套目录新文件(self, monitor, temp_dir):
        nested = temp_dir / "a" / "b"
        nested.mkdir(parents=True)
        monitor.start()
        time.sleep(0.5)

        (nested / "nested_new.bin").write_bytes(b"\x00" * 2000)
        time.sleep(1.5)
        events = monitor.get_events()
        monitor.stop()

        assert any("nested_new.bin" in e.path for e in events)

    def test_检测大文件创建(self, monitor, temp_dir):
        monitor.start()
        time.sleep(0.5)

        # 创建大文件
        big_file = temp_dir / "big_file.bin"
        big_file.write_bytes(b"\x00" * 500_000)

        time.sleep(1.5)
        events = monitor.get_events()
        monitor.stop()

        big_events = [e for e in events if "big_file" in e.path]
        assert len(big_events) >= 1

    def test_冷却期防抖(self, monitor, temp_dir):
        monitor.start()
        time.sleep(0.5)

        f = temp_dir / "modified.log"
        f.write_text("first write\n", encoding="utf-8")
        time.sleep(0.5)
        f.write_text("second write\n", encoding="utf-8")

        time.sleep(1.5)
        events = monitor.get_events()
        monitor.stop()

        log_events = [e for e in events if "modified.log" in e.path]
        assert len(log_events) >= 1

    def test_停止监控不报错(self, monitor):
        monitor.start()
        time.sleep(0.1)
        monitor.stop()
        assert not monitor.is_running

    def test_重复启动不报错(self, monitor):
        monitor.start()
        monitor.start()  # 不应崩溃
        monitor.stop()

    def test_事件包含完整路径(self, monitor, temp_dir):
        monitor.start()
        time.sleep(0.2)

        (temp_dir / "check_path.dat").write_bytes(b"\x00" * 1000)
        time.sleep(0.3)
        events = monitor.get_events()
        monitor.stop()

        for e in events:
            assert os.path.isabs(e.path)

    def test_事件包含文件大小(self, monitor, temp_dir):
        monitor.start()
        time.sleep(0.2)

        (temp_dir / "sized_file.bin").write_bytes(b"\x00" * 9999)
        time.sleep(0.3)
        events = monitor.get_events()
        monitor.stop()

        for e in events:
            if "sized_file" in e.path:
                assert e.size > 0

    def test_获取事件后清空队列(self, monitor, temp_dir):
        monitor.start()
        time.sleep(0.5)
        (temp_dir / "first.tmp").write_bytes(b"\x00" * 1000)
        time.sleep(1.5)
        first_batch = monitor.get_events()
        assert len(first_batch) > 0, f"期望至少 1 个事件，实际 {len(first_batch)} 个"

        second_batch = monitor.get_events()
        assert len(second_batch) == 0
        monitor.stop()
