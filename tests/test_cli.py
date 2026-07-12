"""CLI 命令行测试"""

import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner
from disk_cleaner.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def temp_project():
    """创建临时测试项目"""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "README.md").write_text("# Test")
        (root / "main.py").write_text("print('hello')\n" * 100)
        (root / "test.log").write_text("error\n" * 50)
        (root / "debug.tmp").write_bytes(b"\x00" * 5000)
        sub = root / "build"
        sub.mkdir()
        (sub / "output.o").write_bytes(b"\x00" * 20000)
        yield root


class TestScanCommand:
    """scan 命令测试"""

    def test_扫描目录输出文件列表(self, runner, temp_project):
        result = runner.invoke(cli, ["scan", str(temp_project)])
        assert result.exit_code == 0
        assert "README.md" in result.output or "main.py" in result.output

    def test_top_n限制输出(self, runner, temp_project):
        result = runner.invoke(cli, ["scan", str(temp_project), "--top", "2"])
        assert result.exit_code == 0

    def test_min_size过滤(self, runner, temp_project):
        result = runner.invoke(cli, ["scan", str(temp_project), "--min-size", "10000"])
        assert result.exit_code == 0

    def test_不存在的目录报错(self, runner):
        result = runner.invoke(cli, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_json输出格式(self, runner, temp_project):
        result = runner.invoke(cli, ["scan", str(temp_project), "--format", "json"])
        assert result.exit_code == 0
        # 应该输出有效的 JSON 数组
        import json
        data = json.loads(result.output)
        assert isinstance(data, list)
        for item in data:
            assert "path" in item
            assert "size" in item


class TestAnalyzeCommand:
    """analyze 命令测试"""

    def test_无AI密钥时使用本地分析(self, runner, temp_project):
        result = runner.invoke(cli, [
            "analyze", str(temp_project),
            "--provider", "openai",
        ])
        # 没有 API key 时应该降级到本地分析
        assert result.exit_code == 0

    def test_不支持的后端报错(self, runner, temp_project):
        result = runner.invoke(cli, [
            "analyze", str(temp_project),
            "--provider", "invalid",
        ])
        assert result.exit_code != 0

    def test_预览模式不消耗API(self, runner, temp_project):
        result = runner.invoke(cli, [
            "analyze", str(temp_project),
            "--provider", "ollama",
            "--preview",
        ])
        assert result.exit_code == 0


class TestCLIGeneral:
    """通用 CLI 测试"""

    def test_version命令(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "disk-cleaner" in result.output.lower() or "0.1" in result.output

    def test_help信息(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "analyze" in result.output

    def test_stats命令(self, runner):
        result = runner.invoke(cli, ["stats"])
        assert result.exit_code == 0
