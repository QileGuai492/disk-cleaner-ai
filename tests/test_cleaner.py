"""清理执行器测试"""

import os
import tempfile
from pathlib import Path

import pytest
from disk_cleaner.cleaner.executor import CleanExecutor, BackupManager, CleanResult


@pytest.fixture
def temp_dir():
    """创建临时测试环境"""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # 创建测试文件
        (root / "file_to_clean.tmp").write_text("garbage" * 100, encoding="utf-8")
        (root / "keep_me.txt").write_text("important data", encoding="utf-8")
        sub = root / "subdir"
        sub.mkdir()
        (sub / "nested_file.log").write_text("log data", encoding="utf-8")
        yield root


@pytest.fixture
def backup_root():
    """备份区根目录"""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


class TestCleanResult:
    """清理结果测试"""

    def test_记录成功清理(self):
        result = CleanResult(
            path="/tmp/test.tmp",
            success=True,
            bytes_freed=5000,
            action="moved_to_backup",
            backup_path="/backup/test.tmp",
        )
        assert result.success
        assert result.bytes_freed == 5000
        assert result.action == "moved_to_backup"

    def test_记录失败清理(self):
        result = CleanResult(
            path="/tmp/nonexistent.tmp",
            success=False,
            bytes_freed=0,
            action="delete",
            error="文件不存在",
        )
        assert not result.success
        assert result.error == "文件不存在"


class TestBackupManager:
    """备份管理器测试"""

    def test_创建备份批次(self, backup_root):
        manager = BackupManager(str(backup_root))
        batch_id = manager.create_batch("test batch")
        assert batch_id is not None
        batch_dir = backup_root / batch_id
        assert batch_dir.exists()
        assert (batch_dir / "manifest.json").exists()

    def test_备份文件保持目录结构(self, backup_root, temp_dir):
        manager = BackupManager(str(backup_root))
        batch_id = manager.create_batch("test")
        src_file = temp_dir / "file_to_clean.tmp"

        result = manager.backup_file(str(src_file), batch_id)
        assert result.success
        # 备份后源文件应该被移走
        assert not src_file.exists()

    def test_列出备份批次(self, backup_root):
        import time
        manager = BackupManager(str(backup_root))
        manager.create_batch("batch1")
        time.sleep(0.002)  # 确保时间戳不同
        manager.create_batch("batch2")
        batches = manager.list_batches()
        assert len(batches) == 2

    def test_恢复备份文件(self, backup_root, temp_dir):
        manager = BackupManager(str(backup_root))
        batch_id = manager.create_batch("test")
        original_content = (temp_dir / "file_to_clean.tmp").read_text()

        manager.backup_file(str(temp_dir / "file_to_clean.tmp"), batch_id)
        # 恢复
        results = manager.restore_batch(batch_id)
        assert len(results) > 0
        assert (temp_dir / "file_to_clean.tmp").exists()
        assert (temp_dir / "file_to_clean.tmp").read_text() == original_content

    def test_删除过期批次(self, backup_root, temp_dir):
        manager = BackupManager(str(backup_root))
        batch_id = manager.create_batch("old batch")
        manager.backup_file(str(temp_dir / "file_to_clean.tmp"), batch_id)
        # 删除批次
        success = manager.delete_batch(batch_id)
        assert success
        assert not (backup_root / batch_id).exists()


class TestCleanExecutor:
    """清理执行器测试"""

    def test_移动到备份区(self, temp_dir, backup_root):
        executor = CleanExecutor(backup_dir=str(backup_root))
        files = [str(temp_dir / "file_to_clean.tmp"), str(temp_dir / "subdir" / "nested_file.log")]
        results = executor.clean(files, mode="backup")

        assert len(results) == 2
        for r in results:
            assert r.success

        # 源文件应该已移走
        assert not (temp_dir / "file_to_clean.tmp").exists()

    def test_保留白名单文件(self, temp_dir, backup_root):
        executor = CleanExecutor(backup_dir=str(backup_root))
        executor.add_keep_list(["*.txt", "*keep_me*"])

        files = [str(temp_dir / "file_to_clean.tmp"), str(temp_dir / "keep_me.txt")]
        results = executor.clean(files, mode="backup")

        # keep_me.txt 应该被保留
        assert (temp_dir / "keep_me.txt").exists()
        # file_to_clean.tmp 应该被清理
        assert not (temp_dir / "file_to_clean.tmp").exists()

    def test_计算总释放空间(self, temp_dir, backup_root):
        executor = CleanExecutor(backup_dir=str(backup_root))
        files = [str(temp_dir / "file_to_clean.tmp")]
        total = executor.estimate_freed_space(files)
        assert total > 0

    def test_空文件列表不报错(self, temp_dir, backup_root):
        executor = CleanExecutor(backup_dir=str(backup_root))
        results = executor.clean([], mode="backup")
        assert len(results) == 0

    def test_不存在的文件标记失败(self, temp_dir, backup_root):
        executor = CleanExecutor(backup_dir=str(backup_root))
        results = executor.clean(["/nonexistent/file.xyz"], mode="backup")
        assert len(results) == 1
        assert not results[0].success

    def test_获取清理摘要(self, temp_dir, backup_root):
        executor = CleanExecutor(backup_dir=str(backup_root))
        files = [str(temp_dir / "file_to_clean.tmp")]
        results = executor.clean(files, mode="backup")
        summary = executor.get_summary(results)
        assert summary["total_files"] == 1
        assert summary["success_count"] == 1
        assert summary["total_freed"] > 0

    def test_备份目录不存在时自动创建(self, temp_dir, tmp_path):
        new_backup = tmp_path / "new_backup"
        executor = CleanExecutor(backup_dir=str(new_backup))
        files = [str(temp_dir / "file_to_clean.tmp")]
        results = executor.clean(files, mode="backup")
        assert new_backup.exists()

    def test_清理后返回批次号(self, temp_dir, backup_root):
        executor = CleanExecutor(backup_dir=str(backup_root))
        results = executor.clean([str(temp_dir / "file_to_clean.tmp")], mode="backup")
        assert results[0].success
        assert executor.last_batch_id
        assert executor.backup_manager.file_count(executor.last_batch_id) == 1

    def test_恢复后从清单移除(self, backup_root, temp_dir):
        manager = BackupManager(str(backup_root))
        batch_id = manager.create_batch("test")
        manager.backup_file(str(temp_dir / "file_to_clean.tmp"), batch_id)

        first = manager.restore_batch(batch_id)
        assert first[0].success
        assert manager.file_count(batch_id) == 0

        # 二次恢复不应重复搬运，也不应报成功
        second = manager.restore_batch(batch_id)
        assert second == []

    def test_过期判断优先使用清单时间(self, backup_root, temp_dir):
        import json

        manager = BackupManager(str(backup_root))
        batch_id = manager.create_batch("expired")
        manager.backup_file(str(temp_dir / "file_to_clean.tmp"), batch_id)

        manifest = backup_root / batch_id / "manifest.json"
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["expires_at"] = "2000-01-01T00:00:00"
        manifest.write_text(json.dumps(data), encoding="utf-8")

        assert manager.prune_expired() == 1
        assert not (backup_root / batch_id).exists()
