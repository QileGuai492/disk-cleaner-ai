"""安全策略与清理计划测试。"""

import os

import pytest

from disk_cleaner.cleaner.executor import CleanExecutor
from disk_cleaner.cleaner.safety import SafetyPolicy


def _system_path(*parts):
    drive = os.environ.get("SystemRoot") or "C:\\Windows"
    return os.path.join(drive, *parts)


def test_windows_system_tree_is_blocked():
    if os.name != "nt":
        pytest.skip("Windows 专用保护规则")
    policy = SafetyPolicy()
    decision = policy.validate(_system_path("System32", "kernel32.dll"))
    assert not decision.allowed
    assert "受保护" in decision.reason


def test_program_files_is_blocked():
    if os.name != "nt":
        pytest.skip("Windows 专用保护规则")
    policy = SafetyPolicy()
    root = os.environ.get("ProgramFiles") or "C:\\Program Files"
    decision = policy.validate(os.path.join(root, "SomeApp", "app.exe"))
    assert not decision.allowed


def test_pagefile_is_blocked():
    if os.name != "nt":
        pytest.skip("Windows 专用保护规则")
    drive = (os.environ.get("SystemDrive") or "C:") + "\\"
    decision = SafetyPolicy().validate(os.path.join(drive, "pagefile.sys"))
    assert not decision.allowed


def test_normal_temp_file_is_allowed(tmp_path):
    target = tmp_path / "cache.tmp"
    target.write_text("data", encoding="utf-8")
    assert SafetyPolicy().validate(str(target)).allowed


def test_scan_root_containment(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "inside.txt"
    inside.write_text("data", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("data", encoding="utf-8")

    policy = SafetyPolicy()
    assert policy.validate(str(inside), scan_root=str(root)).allowed
    decision = policy.validate(str(outside), scan_root=str(root))
    assert not decision.allowed
    assert "扫描根目录" in decision.reason


def test_executor_skips_system_path_without_touching_it(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows 专用保护规则")
    executor = CleanExecutor(backup_dir=str(tmp_path / "backup"))
    results = executor.clean([_system_path("System32", "kernel32.dll")], mode="backup")
    assert len(results) == 1
    assert not results[0].success
    assert results[0].action == "skipped"
    assert "受保护" in results[0].error


def test_plan_warns_when_backup_is_on_same_volume(tmp_path):
    target = tmp_path / "junk.tmp"
    target.write_text("data", encoding="utf-8")
    executor = CleanExecutor(backup_dir=str(tmp_path / "backup"))
    plan = executor.plan([str(target)], mode="backup")
    assert plan.allowed
    assert plan.total_bytes == target.stat().st_size
    assert any("同一个分区" in warning for warning in plan.warnings)


def test_plan_has_no_paths_when_all_rejected(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows 专用保护规则")
    executor = CleanExecutor(backup_dir=str(tmp_path / "backup"))
    plan = executor.plan([_system_path("System32", "kernel32.dll")], mode="backup")
    assert not plan.allowed
    assert plan.paths == []
    assert plan.rejected
