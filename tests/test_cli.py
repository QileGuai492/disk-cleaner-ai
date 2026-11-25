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
        (root / "README.md").write_text("# Test", encoding="utf-8")
        (root / "main.py").write_text("print('hello')\n" * 100, encoding="utf-8")
        (root / "test.log").write_text("error\n" * 50, encoding="utf-8")
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


class TestCheckDeps:
    """依赖检查不能再给出误导性的“可以安全处理”。"""

    def test_单文件未发现引用时明确警告(self, runner, tmp_path):
        target = tmp_path / "unknown.dll"
        target.write_bytes(b"MZ" + b"\x00" * 100)

        result = runner.invoke(cli, ["check-deps", str(target)])
        assert result.exit_code == 0
        assert "未发现" in result.output
        assert "不等于安全" in result.output
        assert "可以安全处理" not in result.output

    def test_目录模式只给统计并提示局限(self, runner, tmp_path):
        (tmp_path / "readme.txt").write_text("hello", encoding="utf-8")
        result = runner.invoke(cli, ["check-deps", str(tmp_path)])
        assert result.exit_code == 0
        assert "不给出逐个文件的安全结论" in result.output


class TestRelocate:
    """搬迁命令（不实际创建 Junction）。"""

    def test_搬迁命令调用执行器(self, runner, tmp_path, monkeypatch):
        from disk_cleaner.cleaner.junction import JunctionManager, JunctionResult

        source = tmp_path / "source"
        source.mkdir()
        (source / "data.txt").write_text("data", encoding="utf-8")
        target = tmp_path / "relocated"
        called = {}

        def fake_relocate(src, dst, auto_junction=True):
            called["src"] = src
            called["dst"] = dst
            called["junction"] = auto_junction
            return JunctionResult(
                source=src, target=str(target / "source"),
                action="created", success=True,
            )

        monkeypatch.setattr(JunctionManager, "relocate_directory", staticmethod(fake_relocate))
        result = runner.invoke(cli, ["relocate", str(source), str(target), "-y"])
        assert result.exit_code == 0
        assert "搬迁成功" in result.output
        assert called["junction"] is True


class TestStatsRecording:
    """扫描后 stats 应该有真实数字。"""

    def test_分析后统计有扫描记录(self, runner, tmp_path, monkeypatch):
        import disk_cleaner.cli.main as cli_module

        db_path = tmp_path / "cache.db"
        monkeypatch.setattr(cli_module, "_get_db_path", lambda: str(db_path))

        work = tmp_path / "work"
        work.mkdir()
        (work / "debug.tmp").write_bytes(b"\x00" * 1000)

        analyze_result = runner.invoke(
            cli, ["analyze", str(work), "--provider", "ollama", "--top", "5"]
        )
        assert analyze_result.exit_code == 0

        stats_result = runner.invoke(cli, ["stats"])
        assert stats_result.exit_code == 0
        assert "总扫描次数: 1" in stats_result.output


class TestConfigCommands:
    """统一配置 CLI。"""

    def test_配置初始化与路径(self, runner, tmp_path, monkeypatch):
        path = tmp_path / "config.json"
        monkeypatch.setenv("DISK_CLEANER_CONFIG", str(path))

        result = runner.invoke(cli, ["config", "init"])
        assert result.exit_code == 0
        assert path.exists()

        result = runner.invoke(cli, ["config", "path"])
        assert result.exit_code == 0
        assert str(path) in result.output


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
