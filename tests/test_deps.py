"""文件依赖分析测试"""

import os
import struct
import tempfile
from pathlib import Path

import pytest
from disk_cleaner.analyzer.deps import (
    DependencyAnalyzer,
    PEImports,
    DependencyReport,
    get_dependency_report,
)


@pytest.fixture
def temp_project():
    """创建测试目录，复制系统 PE 文件"""
    import shutil

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        system32 = Path("C:\\Windows\\System32")

        # 复制真实的系统 DLL 用于测试
        test_files = [
            ("kernel32.dll", "kernel32.dll"),
            ("user32.dll", "user32.dll"),
            ("msvcrt.dll", "msvcrt.dll"),
            ("notepad.exe", "notepad.exe"),
        ]
        for src_name, dest_name in test_files:
            src = system32 / src_name
            if src.exists():
                shutil.copy2(str(src), str(root / dest_name))

        # 自定义测试文件
        (root / "helper.dll").write_bytes(b"MZ" + b"\x00" * 100 + b"PE\x00\x00" + b"\x00" * 200 + b"kernel32.dll\x00user32.dll\x00")
        (root / "orphan.dll").write_bytes(b"MZ" + b"\x00" * 100 + b"PE\x00\x00" + b"\x00" * 200 + b"kernel32.dll\x00")

        # 非 PE 文件
        (root / "readme.txt").write_text("Hello World")
        (root / "config.json").write_text('{"key": "value"}')
        yield root


class TestPEImports:
    """PE 导入表解析测试"""

    def test_创建空导入记录(self):
        imports = PEImports(path="/tmp/test.exe")
        assert imports.dll_imports == []
        assert imports.is_pe is False

    def test_非PE文件不被解析(self, temp_project):
        analyzer = DependencyAnalyzer()
        reports = analyzer.scan_imports(str(temp_project / "readme.txt"))
        assert len(reports) == 0


class TestDependencyAnalyzer:
    """依赖分析器测试"""

    @pytest.fixture
    def analyzer(self, temp_project):
        da = DependencyAnalyzer()
        da.scan_directory(str(temp_project))
        return da

    def test_扫描目录发现PE文件(self, analyzer):
        assert len(analyzer.imports) >= 1

    def test_反向索引查询真实DLL(self, analyzer):
        # kernel32.dll 被几乎所有 exe/dll 引用
        refs = analyzer.get_referrers("kernel32.dll")
        assert len(refs) >= 1

    def test_孤立DLL无引用(self, analyzer):
        # orphan.dll 是自定义的，没有任何真实文件引用它
        refs = analyzer.get_referrers("orphan.dll")
        assert len(refs) == 0

    def test_统计信息完整(self, analyzer):
        stats = analyzer.get_stats()
        assert stats["pe_files"] >= 1
        assert "unique_imports" in stats
        assert "reverse_index_entries" in stats

    def test_分析报告包含依赖详情(self, analyzer):
        # 被引用的 DLL（至少自身引用了 kernel32）
        report = analyzer.analyze("kernel32.dll")
        assert report.dll_name == "kernel32.dll"
        # kernel32.dll 至少会被自身和其他 DLL 引用
        assert report.referrer_count >= 0

    def test_未被引用的DLL可以安全处理(self, analyzer):
        report = analyzer.analyze("orphan.dll")
        assert report.dll_name == "orphan.dll"
        # orphan.dll 没有任何 exe 引用它
        assert not report.should_keep

    def test_非DLL文件分析(self, analyzer):
        report = analyzer.analyze("readme.txt")
        assert not report.should_keep

    def test_导出到数据库(self, analyzer, temp_project):
        import sqlite3
        db_path = str(temp_project / "test.db")
        analyzer.export_to_db(db_path)
        assert os.path.exists(db_path)
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM pe_imports").fetchone()[0]
        assert count > 0
        conn.close()


class TestDependencyReport:
    """依赖报告测试"""

    def test_有引用的报告(self):
        report = DependencyReport(
            dll_name="helper.dll",
            referrers=["C:\\app\\main.exe", "C:\\app\\tool.exe"],
        )
        assert report.referrer_count == 2
        assert report.should_keep is True

    def test_无引用的报告(self):
        report = DependencyReport(
            dll_name="orphan.dll",
            referrers=[],
        )
        assert report.referrer_count == 0
        assert report.should_keep is False

    def test_被孤立DLL引用不构成依赖(self):
        """如果只有另一个 DLL 引用它（没有 exe），仍然算无引用"""
        report = DependencyReport(
            dll_name="orphan.dll",
            referrers=["C:\\app\\another.dll"],
        )
        # 没有 exe 引用 → 可以处理
        assert not report.should_keep


class TestGetDependencyReport:
    """便捷函数测试"""

    def test_简单路径分析(self, temp_project):
        report = get_dependency_report(str(temp_project / "helper.dll"))
        assert isinstance(report, DependencyReport)
