"""应用指纹库测试"""

import json
import tempfile
from pathlib import Path

import pytest
from disk_cleaner.analyzer.fingerprints import (
    AppFingerprint,
    FingerprintDB,
    BUILTIN_FINGERPRINTS,
)


class TestAppFingerprint:
    """指纹数据结构测试"""

    def test_创建指纹(self):
        fp = AppFingerprint(
            app_name="测试应用",
            category="tool",
            fingerprints=["*/TestApp/**", "*/TestApp/cache/**"],
            cleanup_hint="可安全清理",
            removable=True,
        )
        assert fp.app_name == "测试应用"
        assert fp.category == "tool"
        assert len(fp.fingerprints) == 2


class TestFingerprintDB:
    """指纹数据库测试"""

    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as td:
            yield FingerprintDB(db_dir=td)

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 模拟 Chrome 缓存路径
            chrome_cache = root / "Google" / "Chrome" / "User Data" / "Default" / "Cache"
            chrome_cache.mkdir(parents=True)
            (chrome_cache / "data_0").write_bytes(b"\x00" * 5000)
            (chrome_cache / "index").write_bytes(b"\x00" * 1000)

            # 模拟 Python 缓存
            pycache = root / "myproject" / "__pycache__"
            pycache.mkdir(parents=True)
            (pycache / "module.cpython-312.pyc").write_bytes(b"\x00" * 500)
            (root / "myproject" / "script.pyc").write_bytes(b"\x00" * 200)

            # 非匹配文件
            (root / "important.docx").write_text("重要文档", encoding="utf-8")
            yield root

    def test_内置指纹已加载(self, db):
        assert db.app_count >= 10

    def test_匹配Chrome缓存路径(self, db, temp_dir):
        chrome_path = str(temp_dir / "Google" / "Chrome" / "User Data" / "Default" / "Cache" / "data_0")
        matches = db.match(chrome_path)
        chrome_match = [m for m in matches if "Chrome" in m.app_name]
        assert len(chrome_match) >= 1

    def test_匹配Python缓存路径(self, db, temp_dir):
        pyc_path = str(temp_dir / "myproject" / "__pycache__" / "module.cpython-312.pyc")
        matches = db.match(pyc_path)
        py_match = [m for m in matches if "Python" in m.app_name]
        assert len(py_match) >= 1

    def test_不匹配普通文件(self, db, temp_dir):
        docx_path = str(temp_dir / "important.docx")
        matches = db.match(docx_path)
        assert len(matches) == 0

    def test_扫描目录返回映射(self, db, temp_dir):
        app_files = db.scan_directory(str(temp_dir))
        python_files = app_files.get("Python 缓存", [])
        chrome_files = app_files.get("Chrome 缓存", [])
        assert len(python_files) >= 2  # pyc + pycache dir
        assert len(chrome_files) >= 2  # data_0 + index

    def test_获取清理建议(self, db, temp_dir):
        suggestions = db.get_cleanup_suggestions(str(temp_dir))
        assert len(suggestions) >= 2
        # Python 缓存应该在最前面（按大小排序）
        for s in suggestions:
            assert s["total_size_mb"] >= 0
            assert s["file_count"] > 0

    def test_清理建议包含清理提示(self, db, temp_dir):
        suggestions = db.get_cleanup_suggestions(str(temp_dir))
        for s in suggestions:
            assert "cleanup_hint" in s
            assert "sample_paths" in s

    def test_添加自定义指纹(self, db):
        fp = AppFingerprint(
            app_name="自定义应用",
            category="tool",
            fingerprints=["*/CustomApp/**"],
            cleanup_hint="测试",
        )
        db.add_fingerprint(fp)
        assert db.app_count >= 11

    def test_保存和加载自定义指纹(self, db):
        fp = AppFingerprint(
            app_name="持久化测试",
            category="test",
            fingerprints=["*/PersistTest/**"],
            cleanup_hint="测试持久化",
        )
        db.add_fingerprint(fp)
        db.save()

        # 重新加载
        db2 = FingerprintDB(db_dir=db.db_dir)
        persist = [f for f in db2._fingerprints if f.app_name == "持久化测试"]
        assert len(persist) == 1
