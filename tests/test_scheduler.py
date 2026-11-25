"""定时扫描配置、状态与单次执行测试。"""

import json

from disk_cleaner.cli.scheduler import ScanScheduler


def test_config_round_trip(tmp_path):
    path = tmp_path / "schedule.json"
    scheduler = ScanScheduler(str(path))
    scheduler.config.interval_hours = 6
    scheduler.config.scan_paths = [str(tmp_path)]
    scheduler.config.auto_clean = False
    scheduler._save_config()

    loaded = ScanScheduler(str(path))
    assert loaded.config.interval_hours == 6
    assert loaded.config.scan_paths == [str(tmp_path)]
    assert loaded.config.auto_clean is False


def test_run_once_calls_scan_and_persists_state(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    scheduler = ScanScheduler(str(tmp_path / "schedule.json"))
    scheduler.config.scan_paths = [str(target)]
    calls = []
    scheduler.set_scan_function(lambda path: calls.append(path))

    scheduler.run_once()

    assert calls == [str(target)]
    assert scheduler.state_path.endswith("schedule_state.json")
    assert scheduler.status["last_scan"]
    assert scheduler.status["next_scan"]


def test_config_with_utf8_bom(tmp_path):
    path = tmp_path / "schedule.json"
    path.write_text(
        json.dumps({
            "scan_paths": [str(tmp_path)],
            "interval_hours": 12,
            "auto_clean": False,
            "notify_on_findings": True,
            "enabled": True,
        }),
        encoding="utf-8-sig",
    )
    scheduler = ScanScheduler(str(path))
    assert scheduler.config.interval_hours == 12
    assert scheduler.config.scan_paths == [str(tmp_path)]


def test_pid_file_lifecycle(tmp_path):
    scheduler = ScanScheduler(str(tmp_path / "schedule.json"))
    scheduler.write_pid(12345)
    assert scheduler.read_pid() == 12345
    scheduler.remove_pid()
    assert scheduler.read_pid() is None
