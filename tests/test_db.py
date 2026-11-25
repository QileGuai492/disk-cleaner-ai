"""数据层测试"""

import os
import tempfile
from pathlib import Path

import pytest
from disk_cleaner.db.models import Database, AnalysisCache, ScanRecord


@pytest.fixture
def db():
    """创建临时数据库"""
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        database = Database(db_path)
        database.initialize()
        yield database
        database.close()


class TestDatabase:
    """数据库初始化与连接测试"""

    def test_数据库文件创建(self, db):
        assert os.path.exists(db.path)

    def test_schema_version(self, db):
        assert db.schema_version >= 2

    def test_表结构创建(self, db):
        tables = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t[0] for t in tables]
        assert "analysis_cache" in table_names
        assert "rules" in table_names
        assert "scan_records" in table_names


class TestAnalysisCache:
    """分析缓存 CRUD 测试"""

    def test_写入和读取缓存(self, db):
        cache = AnalysisCache(db)
        cache.upsert(
            file_path="/tmp/test.tmp",
            mtime=1700000000,
            size_bytes=5000,
            decision="safe_to_delete",
            confidence=0.95,
            reason="临时文件",
            risk="none",
            ai_model="gpt-4o-mini",
        )
        result = cache.get("/tmp/test.tmp", 1700000000, 5000)
        assert result is not None
        assert result["decision"] == "safe_to_delete"
        assert result["confidence"] == 0.95

    def test_缓存未命中(self, db):
        cache = AnalysisCache(db)
        result = cache.get("/nonexistent/file.txt", 0, 0)
        assert result is None

    def test_mtime变化导致缓存失效(self, db):
        cache = AnalysisCache(db)
        cache.upsert("/tmp/test.tmp", 1700000000, 5000, "safe_to_delete", 0.95, "", "", "")
        # 相同路径、不同 mtime
        result = cache.get("/tmp/test.tmp", 1700000001, 5000)
        assert result is None

    def test_size变化导致缓存失效(self, db):
        cache = AnalysisCache(db)
        cache.upsert("/tmp/test.tmp", 1700000000, 5000, "safe_to_delete", 0.95, "", "", "")
        result = cache.get("/tmp/test.tmp", 1700000000, 5001)
        assert result is None

    def test_覆盖写入同一条缓存(self, db):
        cache = AnalysisCache(db)
        cache.upsert("/tmp/test.tmp", 1700000000, 5000, "safe_to_delete", 0.95, "", "", "gpt-4o-mini")
        cache.upsert("/tmp/test.tmp", 1700000000, 5000, "keep", 1.0, "", "", "claude")
        result = cache.get("/tmp/test.tmp", 1700000000, 5000)
        assert result["decision"] == "keep"
        assert result["ai_model"] == "claude"

    def test_批量写入缓存(self, db):
        cache = AnalysisCache(db)
        cache.upsert_many([
            {
                "file_path": f"/tmp/batch_{i}.tmp",
                "mtime": 1700000000,
                "size_bytes": 1000,
                "decision": "safe_to_delete",
                "confidence": 0.95,
                "reason": "批量",
                "risk": "none",
                "ai_model": "test",
            }
            for i in range(3)
        ])
        keys = [(f"/tmp/batch_{i}.tmp", 1700000000, 1000) for i in range(3)]
        assert len(cache.batch_get(keys)) == 3

    def test_批量查询缓存命中率(self, db):
        cache = AnalysisCache(db)
        # 写入 10 条缓存
        for i in range(10):
            cache.upsert(f"/tmp/file_{i}.tmp", 1700000000, 1000, "safe_to_delete", 0.95, "", "", "")
        # 查询 10 条，命中 10 条
        keys = [(f"/tmp/file_{i}.tmp", 1700000000, 1000) for i in range(10)]
        results = cache.batch_get(keys)
        assert len(results) == 10

    def test_清理孤立缓存(self, db):
        cache = AnalysisCache(db)
        cache.upsert("/tmp/deleted_file.tmp", 1700000000, 5000, "safe_to_delete", 0.95, "", "", "")
        cache.purge_orphaned(
            existing_paths={"file1.txt": None}  # deleted_file.tmp 不在集合中
        )
        result = cache.get("/tmp/deleted_file.tmp", 1700000000, 5000)
        assert result is None  # 已被清理


class TestRulesTable:
    """规则表 CRUD 测试"""

    def test_写入和读取规则(self, db):
        db.save_rule(
            pattern="*.tmp",
            decision="safe_to_delete",
            confidence=0.99,
            source="ai_learned",
        )
        rules = db.get_rules()
        assert len(rules) >= 1
        pattern_exists = any(r["pattern"] == "*.tmp" for r in rules)
        assert pattern_exists

    def test_规则不会重复存储(self, db):
        db.save_rule("*.tmp", "safe_to_delete", 0.99, "ai_learned")
        db.save_rule("*.tmp", "safe_to_delete", 0.99, "ai_learned")
        rules = [r for r in db.get_rules() if r["pattern"] == "*.tmp"]
        assert len(rules) == 1

    def test_按来源过滤规则(self, db):
        db.save_rule("*.tmp", "safe_to_delete", 0.99, "ai_learned")
        db.save_rule("*.log", "likely_safe", 0.80, "user_defined")
        user_rules = db.get_rules(source="user_defined")
        assert all(r["source"] == "user_defined" for r in user_rules)


class TestScanRecords:
    """扫描记录测试"""

    def test_记录扫描历史(self, db):
        records = ScanRecord(db)
        scan_id = records.start_scan(path="C:\\", file_count=50000)
        assert scan_id > 0

    def test_完成扫描记录(self, db):
        records = ScanRecord(db)
        scan_id = records.start_scan(path="C:\\", file_count=1000)
        records.finish_scan(scan_id, analyzed_count=800, cleaned_count=50, bytes_freed=1_000_000_000)
        history = records.get_history(limit=5)
        assert len(history) > 0
        latest = history[0]
        assert latest["bytes_freed"] == 1_000_000_000

    def test_获取清理统计(self, db):
        records = ScanRecord(db)
        # 记录两次扫描
        sid1 = records.start_scan(path="C:\\", file_count=1000)
        records.finish_scan(sid1, analyzed_count=500, cleaned_count=100, bytes_freed=500_000_000)
        sid2 = records.start_scan(path="D:\\", file_count=2000)
        records.finish_scan(sid2, analyzed_count=1000, cleaned_count=200, bytes_freed=1_000_000_000)

        stats = records.get_total_stats()
        assert stats["total_scans"] == 2
        assert stats["total_files_cleaned"] == 300
        assert stats["total_bytes_freed"] == 1_500_000_000

    def test_清理记录与扫描记录分开统计(self, db):
        records = ScanRecord(db)
        sid = records.start_scan(path="C:\\", file_count=1000)
        records.finish_scan(sid, analyzed_count=800, cleaned_count=0, bytes_freed=0)
        records.record_cleanup(cleaned_count=5, bytes_moved=1000, bytes_freed=500)

        stats = records.get_total_stats()
        assert stats["total_scans"] == 1
        assert stats["total_files_cleaned"] == 5
        assert stats["total_bytes_freed"] == 500
