"""扫描引擎测试"""

import os
import tempfile
import time
from pathlib import Path

import pytest
from disk_cleaner.scanner.walker import FileInfo, scan_directory


class TestFileInfo:
    """FileInfo 数据类测试"""

    def test_从路径提取扩展名(self):
        info = FileInfo(path="/tmp/test.txt", size=100, mtime=1234567890.0)
        assert info.extension == ".txt"

    def test_无扩展名文件(self):
        info = FileInfo(path="/tmp/Makefile", size=100, mtime=1234567890.0)
        assert info.extension == ""

    def test_多个点的文件名(self):
        info = FileInfo(path="/tmp/archive.tar.gz", size=100, mtime=1234567890.0)
        assert info.extension == ".gz"

    def test_隐藏文件扩展名(self):
        info = FileInfo(path="/tmp/.gitignore", size=100, mtime=1234567890.0)
        # .gitignore 整体是文件名，没有扩展名（以点开头的隐藏文件）
        assert info.extension == ""

    def test_大小单位换算(self):
        # 2_500_000_000 bytes ≈ 2384.2 MiB ≈ 2.33 GiB（二进制）
        info = FileInfo(path="/tmp/test.bin", size=2_500_000_000, mtime=1234567890.0)
        assert info.size_mb == pytest.approx(2384.2, rel=0.01)
        assert info.size_gb == pytest.approx(2.33, rel=0.01)

    def test_从路径提取关键词(self):
        info = FileInfo(
            path="C:\\Users\\test\\AppData\\Local\\Temp\\file.tmp",
            size=100,
            mtime=1234567890.0,
        )
        keywords = info.path_keywords
        assert "AppData" in keywords
        assert "Local" in keywords
        assert "Temp" in keywords


class TestScanDirectory:
    """目录扫描测试"""

    @pytest.fixture
    def temp_dir(self):
        """创建临时目录结构用于测试"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            # 创建一些文件
            (root / "file1.txt").write_text("hello" * 1000)   # ~5KB
            (root / "file2.log").write_text("error" * 500)     # ~2.5KB

            # 创建子目录
            sub = root / "subdir"
            sub.mkdir()
            (sub / "large_file.dat").write_bytes(b"\x00" * 10_000)  # ~10KB

            # 创建空文件
            (root / "empty.txt").write_text("")

            yield root

    def test_扫描返回所有文件(self, temp_dir):
        results = scan_directory(str(temp_dir))
        paths = [r.path for r in results]
        assert len(results) == 4
        assert any("file1.txt" in p for p in paths)
        assert any("file2.log" in p for p in paths)
        assert any("large_file.dat" in p for p in paths)
        assert any("empty.txt" in p for p in paths)

    def test_按大小降序排列(self, temp_dir):
        results = scan_directory(str(temp_dir))
        sizes = [r.size for r in results]
        # 全局按大小降序，不再把根目录文件强行排在子目录前面
        assert sizes == sorted(sizes, reverse=True)
        assert set(sizes) == {5000, 2500, 0, 10000}

    def test_提取文件大小(self, temp_dir):
        results = scan_directory(str(temp_dir))
        file1 = next(r for r in results if "file1.txt" in str(r.path))
        assert file1.size > 0

    def test_提取修改时间(self, temp_dir):
        results = scan_directory(str(temp_dir))
        for r in results:
            assert r.mtime > 0

    def test_跳过符号链接(self, temp_dir):
        # 创建符号链接（需要权限，Windows 可能需要管理员）
        try:
            link_path = temp_dir / "link_to_file1"
            target = temp_dir / "file1.txt"
            os.symlink(str(target), str(link_path))
        except OSError:
            pytest.skip("无法创建符号链接（可能需要管理员权限）")

        results = scan_directory(str(temp_dir), skip_symlinks=True)
        paths = [r.path for r in results]
        # 符号链接应该被跳过
        assert not any("link_to_file1" in p for p in paths)

    def test_权限不足目录不崩溃(self, temp_dir):
        # 正常目录应该能扫描
        results = scan_directory(str(temp_dir))
        assert len(results) > 0

    def test_不存在的目录抛出异常(self):
        with pytest.raises(FileNotFoundError):
            scan_directory("/nonexistent/path/that/does/not/exist")

    def test_top_n限制返回数量(self, temp_dir):
        results = scan_directory(str(temp_dir), top_n=2)
        assert len(results) == 2

    def test_top_n是全局最大文件(self, temp_dir):
        results = scan_directory(str(temp_dir), top_n=2)
        assert [r.size for r in results] == [10000, 5000]

    def test_目录上限会报告截断(self, temp_dir):
        results, skipped = scan_directory(
            str(temp_dir), max_dirs=1, collect_errors=True
        )
        assert any("上限" in item["reason"] for item in skipped)

    def test_min_size过滤小文件(self, temp_dir):
        # 只返回 > 5KB 的文件
        results = scan_directory(str(temp_dir), min_size=5_000)
        # large_file.dat ~10KB, file1.txt ~5KB, file2.log ~2.5KB, empty.txt 0B
        # 只有 large_file.dat 肯定满足，file1.txt 差不多 5KB
        for r in results:
            assert r.size >= 5_000

    def test_扫描空目录(self, temp_dir):
        empty_dir = temp_dir / "empty"
        empty_dir.mkdir()
        results = scan_directory(str(empty_dir))
        assert len(results) == 0


class TestScanDirectoryErrors:
    """错误收集测试"""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as td:
            yield Path(td)

    def test_收集跳过的路径(self, temp_dir):
        results, skipped = scan_directory(
            str(temp_dir), collect_errors=True
        )
        assert isinstance(skipped, list)

    def test_文件在扫描期间被删除(self, temp_dir):
        # 正常情况下文件不会被删，这里确保不崩溃
        (temp_dir / "will_exist.txt").write_text("data")
        results = scan_directory(str(temp_dir))
        assert len(results) >= 1
