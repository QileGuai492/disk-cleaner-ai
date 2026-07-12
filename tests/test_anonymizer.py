"""路径脱敏测试"""

import pytest
from disk_cleaner.analyzer.anonymizer import PathAnonymizer


class TestPathAnonymizer:
    """路径脱敏测试"""

    @pytest.fixture
    def anon(self):
        return PathAnonymizer(level="strict")

    def test_替换Windows用户名(self, anon):
        path = r"C:\Users\zhangsan\Documents\project\file.txt"
        result = anon.anonymize(path)
        assert "zhangsan" not in result
        assert "<USER>" in result

    def test_保留系统目录结构(self, anon):
        path = r"C:\Users\test\AppData\Local\Temp\file.tmp"
        result = anon.anonymize(path)
        assert "AppData" in result
        assert "Local" in result
        assert "Temp" in result
        # 系统路径保持可读
        assert "file.tmp" in result

    def test_保留扩展名信息(self, anon):
        path = r"C:\Users\test\Downloads\setup.exe"
        result = anon.anonymize(path)
        assert ".exe" in result

    def test_替换中文目录名(self, anon):
        path = r"D:\照片\2024\三亚旅行\IMG_001.jpg"
        result = anon.anonymize(path)
        assert "照片" not in result
        assert "三亚旅行" not in result
        # 但保留层级结构
        assert result.count("\\") >= 3

    def test_替换项目目录名(self, anon):
        path = r"D:\Projects\某银行\风控系统\src\main.py"
        result = anon.anonymize(path)
        assert "某银行" not in result
        assert "风控系统" not in result
        assert "main.py" in result
        assert "src" in result

    def test_moderate级别保留部分信息(self):
        anon = PathAnonymizer(level="moderate")
        path = r"C:\Users\zhangsan\Downloads\report.pdf"
        result = anon.anonymize(path)
        # moderate 级别: 用户名可能被替换
        assert "report.pdf" in result

    def test_minimal级别最少脱敏(self):
        anon = PathAnonymizer(level="minimal")
        path = r"C:\Users\test\Desktop\readme.txt"
        result = anon.anonymize(path)
        assert "readme.txt" in result

    def test_批量脱敏文件列表(self, anon):
        paths = [
            r"C:\Users\zhangsan\Documents\密码.txt",
            r"C:\Users\zhangsan\Desktop\work\方案.docx",
            r"D:\Projects\secret\config.json",
        ]
        results = anon.anonymize_batch(paths)
        assert len(results) == 3
        for r in results:
            assert "zhangsan" not in r

    def test_空路径不报错(self, anon):
        result = anon.anonymize("")
        assert result == ""

    def test_扩展名黑名单检测(self):
        anon = PathAnonymizer()
        assert anon.is_blocked_extension("file.env") is True
        assert anon.is_blocked_extension("file.pem") is True
        assert anon.is_blocked_extension("file.txt") is False
        assert anon.is_blocked_extension("file.jpg") is False
