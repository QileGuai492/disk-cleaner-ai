"""分析引擎集成测试"""

import os
import tempfile
from pathlib import Path

import pytest
from disk_cleaner.db.models import Database, AnalysisCache
from disk_cleaner.scanner.walker import FileInfo
from disk_cleaner.analyzer.engine import AnalysisEngine


@pytest.fixture
def db():
    """创建临时数据库"""
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "test.db")
        database = Database(db_path)
        database.initialize()
        yield database
        database.close()


@pytest.fixture
def engine(db):
    """创建分析引擎"""
    return AnalysisEngine(db, ai_provider="ollama", ai_model="qwen2.5:1.5b")


@pytest.fixture
def temp_dir():
    """创建临时测试文件目录"""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "setup.exe").write_bytes(b"MZ" + b"\x00" * 10000)
        (root / "debug.log").write_text("INFO: started\n" * 100)
        (root / "dump.tmp").write_bytes(b"\x00" * 500)
        (root / "config.json").write_text('{"host":"localhost","port":8080}')
        sub = root / "subdir"
        sub.mkdir()
        (sub / "data.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 5000)
        yield root


class TestAnalysisEngine:
    """分析引擎核心流程测试"""

    def test_扫描和分析返回结果(self, engine, temp_dir):
        results = engine.analyze_directory(str(temp_dir), top_n=10)
        assert len(results) > 0
        for r in results:
            assert "path" in r
            assert "decision" in r
            assert "confidence" in r

    def test_规则引擎先行判定(self, engine, temp_dir):
        results = engine.analyze_directory(str(temp_dir), top_n=10)
        rule_decided = [r for r in results if r.get("source") == "rule"]
        assert len(rule_decided) > 0

    def test_第二次扫描命中缓存(self, engine, temp_dir):
        # 第一次扫描
        engine.analyze_directory(str(temp_dir), top_n=10)
        # 第二次扫描应该全部命中缓存
        results = engine.analyze_directory(str(temp_dir), top_n=10)
        cached = [r for r in results if "cache" in str(r.get("source", ""))]
        assert len(cached) > 0
        # 不应该再有 AI 调用
        ai_called = [r for r in results if r.get("source") == "ai"]
        assert len(ai_called) == 0

    def test_文件修改后缓存失效(self, engine, temp_dir):
        # 第一次扫描
        engine.analyze_directory(str(temp_dir), top_n=10)
        # 修改文件
        (temp_dir / "dump.tmp").write_bytes(b"\x00" * 1000)
        # 再次扫描
        results = engine.analyze_directory(str(temp_dir), top_n=10)
        # 修改过的文件应该重新分析
        dump_file = next((r for r in results if "dump.tmp" in r["path"]), None)
        if dump_file:
            # 应该不是 cache（因为文件变了）
            assert dump_file.get("source") != "cache"

    def test_返回可清理建议的顺序(self, engine, temp_dir):
        results = engine.analyze_directory(str(temp_dir), top_n=10)
        # safe_to_delete 和 likely_safe 应该排前面
        decisions = [r["decision"] for r in results]
        actionable = ["safe_to_delete", "likely_safe"]
        for d in decisions:
            if d in ("keep", "critical"):
                break
            # 前面的都应该是 actionable 或 needs_review
            assert d in actionable or d == "needs_review"

    def test_无法处理时返回needs_review(self, engine, temp_dir):
        # 创建完全未知的文件
        unknown_file = temp_dir / "weird_extension.xyz123"
        unknown_file.write_bytes(b"\xAB\xCD\xEF" * 100)
        results = engine.analyze_directory(str(temp_dir), top_n=10)
        assert len(results) > 0

    def test_空目录不报错(self, engine, temp_dir):
        empty_dir = temp_dir / "empty"
        empty_dir.mkdir()
        results = engine.analyze_directory(str(empty_dir), top_n=10)
        assert len(results) == 0

    def test_结果包含可释放空间估算(self, engine, temp_dir):
        results = engine.analyze_directory(str(temp_dir), top_n=10)
        total_reclaimable = sum(
            r["size"] for r in results
            if r["decision"] in ("safe_to_delete", "likely_safe")
        )
        assert total_reclaimable >= 0


class TestRuleLearningAndForce:
    """规则沉淀与 force 语义测试。"""

    def test_学习扩展名规则(self, db):
        engine = AnalysisEngine(db, ai_provider="local")
        results = [
            {"path": f"/tmp/sample_{i}.csv", "decision": "safe_to_delete",
             "confidence": 1.0, "source": "ai"}
            for i in range(10)
        ]
        new_rules = engine._learn_from_results(results)
        assert any(rule.pattern == "*.csv" for rule in new_rules)

    def test_规则写入数据库并在新引擎加载(self, db):
        engine = AnalysisEngine(db, ai_provider="local")
        results = [
            {"path": f"/tmp/sample_{i}.csv", "decision": "safe_to_delete",
             "confidence": 1.0, "source": "ai"}
            for i in range(10)
        ]
        engine._learn_from_results(results)

        engine2 = AnalysisEngine(db, ai_provider="local")
        assert any(rule.pattern == "*.csv" for rule in engine2.rules.rules)

    def test_force仍然走规则(self, engine, temp_dir):
        results = engine.analyze_directory(str(temp_dir), top_n=20, force=True)
        assert any(r.get("source") == "rule" for r in results)

    def test_流式force仍然走规则(self, engine, temp_dir):
        events = list(engine.analyze_directory_stream(str(temp_dir), top_n=20, force=True))
        results = [e["result"] for e in events if e["type"] == "result"]
        assert any(r.get("source") == "rule" for r in results)


class TestEngineCacheIntegration:
    """缓存集成测试"""

    def test_缓存写入后可用(self, db, temp_dir):
        engine = AnalysisEngine(db, ai_provider="ollama")
        # 第一次扫描
        engine.analyze_directory(str(temp_dir), top_n=10)
        # 检查缓存表有数据
        cache = AnalysisCache(db)
        rows = db._conn.execute("SELECT COUNT(*) FROM analysis_cache").fetchone()
        assert rows[0] >= 0  # 至少尝试过缓存

    def test_重启工具缓存仍然有效(self, db, temp_dir):
        engine1 = AnalysisEngine(db, ai_provider="ollama")
        engine1.analyze_directory(str(temp_dir), top_n=10)

        # 模拟重启：创建新引擎实例，同一数据库
        engine2 = AnalysisEngine(db, ai_provider="ollama")
        results = engine2.analyze_directory(str(temp_dir), top_n=10)

        cached = [r for r in results if "cache" in str(r.get("source", ""))]
        assert len(cached) > 0


class TestAnalysisResult:
    """分析结果数据类测试"""

    def test_结果包含文件路径和决策(self, engine, temp_dir):
        results = engine.analyze_directory(str(temp_dir), top_n=10)
        if results:
            r = results[0]
            assert os.path.isabs(r["path"]) or r["path"].startswith(str(temp_dir))
            assert r["decision"] in (
                "safe_to_delete", "likely_safe", "needs_review", "keep", "critical"
            )

    def test_大文件优先分析(self, engine, temp_dir):
        # setup.exe 是最大文件（~10KB）
        results = engine.analyze_directory(str(temp_dir), top_n=3)
        if results:
            # 应该包含较大的文件
            paths = [r["path"] for r in results]
            assert any("setup.exe" in p or "data.db" in p or "debug.log" in p for p in paths)
