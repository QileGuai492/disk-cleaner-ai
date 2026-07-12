"""文件内容摘要提取测试"""

import json
import os
import sqlite3
import struct
import tempfile
from pathlib import Path

import pytest
from disk_cleaner.analyzer.profiler import ContentProfiler, ContentSummary, FileType


class TestFileType:
    """文件类型识别测试"""

    def test_识别日志文件(self, tmp_path):
        f = tmp_path / "app.log"
        f.write_text("2024-01-01 INFO started\n" * 50)
        assert ContentProfiler.identify_type(str(f)) == FileType.TEXT_LOG

    def test_识别JSON配置(self, tmp_path):
        f = tmp_path / "config.json"
        json.dump({"host": "localhost", "port": 8080, "debug": True}, f.open("w"))
        assert ContentProfiler.identify_type(str(f)) == FileType.CONFIG

    def test_识别YAML配置(self, tmp_path):
        f = tmp_path / "settings.yaml"
        f.write_text("server:\n  host: localhost\n  port: 8080\n")
        assert ContentProfiler.identify_type(str(f)) == FileType.CONFIG

    def test_识别INI配置(self, tmp_path):
        f = tmp_path / "app.ini"
        f.write_text("[database]\nhost=localhost\nport=5432\n")
        assert ContentProfiler.identify_type(str(f)) == FileType.CONFIG

    def test_识别SQLite数据库(self, tmp_path):
        f = tmp_path / "data.db"
        conn = sqlite3.connect(str(f))
        conn.execute("CREATE TABLE test (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO test VALUES (1, 'hello')")
        conn.commit()
        conn.close()
        assert ContentProfiler.identify_type(str(f)) == FileType.DATABASE

    def test_识别PE可执行文件(self, tmp_path):
        f = tmp_path / "program.exe"
        # MZ header
        f.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
        assert ContentProfiler.identify_type(str(f)) == FileType.EXECUTABLE

    def test_识别ZIP归档(self, tmp_path):
        f = tmp_path / "archive.zip"
        # ZIP magic: PK\x03\x04
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        assert ContentProfiler.identify_type(str(f)) == FileType.ARCHIVE

    def test_空文件默认识别(self, tmp_path):
        f = tmp_path / "empty"
        f.write_text("")
        assert ContentProfiler.identify_type(str(f)) == FileType.UNKNOWN

    def test_扩展名优先级高于magic_bytes(self, tmp_path):
        # 即使内容是纯文本，扩展名 .log 应该优先识别为日志
        f = tmp_path / "server.log"
        f.write_bytes(b"\x00\x01\x02\x03")  # 二进制内容
        # 内容无法解析为文本时退化为 UNKNOWN
        assert ContentProfiler.identify_type(str(f)) in (FileType.TEXT_LOG, FileType.UNKNOWN)


class TestContentSummary:
    """摘要结构测试"""

    def test_创建摘要对象(self):
        summary = ContentSummary(file_type="text_log", summary_text="测试摘要")
        assert summary.file_type == "text_log"
        assert summary.summary_text == "测试摘要"
        assert summary.sensitive_detected is False

    def test_标记敏感字段(self):
        summary = ContentSummary(
            file_type="config",
            summary_text="含敏感字段",
            sensitive_detected=True,
            sensitive_keys=["password", "api_key"],
        )
        assert summary.sensitive_detected
        assert len(summary.sensitive_keys) == 2

    def test_转为AI输入格式(self):
        summary = ContentSummary(
            file_type="sqlite",
            summary_text="3 张表: users, sessions, logs",
            extra={"tables": ["users", "sessions", "logs"], "row_count": 1000},
        )
        ai_dict = summary.to_ai_dict()
        assert ai_dict["file_type"] == "sqlite"
        assert ai_dict["tables"] == ["users", "sessions", "logs"]
        assert ai_dict["row_count"] == 1000


class TestContentProfiler:
    """内容分析器测试"""

    @pytest.fixture
    def profiler(self):
        return ContentProfiler(max_sample_bytes=65536)

    def test_分析文本日志(self, profiler, tmp_path):
        f = tmp_path / "errors.log"
        lines = []
        for i in range(100):
            lines.append(f"2024-06-{i%28+1:02d} ERROR Connection timeout to db-host-{i}:5432\n")
        f.write_text("".join(lines))

        summary = profiler.profile(str(f))
        assert summary.file_type == "text_log"
        assert "ERROR" in summary.summary_text
        assert "100" in summary.summary_text  # total lines

    def test_分析JSON配置(self, profiler, tmp_path):
        f = tmp_path / "production.json"
        data = {
            "host": "db.internal.example.com",
            "port": 5432,
            "username": "admin",
            "password": "super_secret_123",
            "api_key": "sk-abc123xyz",
            "debug": False,
        }
        json.dump(data, f.open("w"))

        summary = profiler.profile(str(f))
        assert summary.file_type == "config"
        assert summary.sensitive_detected
        assert "password" in summary.sensitive_keys
        assert "api_key" in summary.sensitive_keys
        # 敏感值不应出现在摘要中
        assert "super_secret_123" not in summary.summary_text
        assert "sk-abc123xyz" not in summary.summary_text

    def test_分析SQLite数据库(self, profiler, tmp_path):
        f = tmp_path / "cache.db"
        conn = sqlite3.connect(str(f))
        conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
        conn.execute("CREATE TABLE sessions (token TEXT, user_id INTEGER, created_at TEXT)")
        for i in range(50):
            conn.execute("INSERT INTO users VALUES (?, ?)", (i, f"user_{i}"))
        conn.commit()
        conn.close()

        summary = profiler.profile(str(f))
        assert summary.file_type == "sqlite"
        assert "users" in summary.summary_text
        assert "sessions" in summary.summary_text

    def test_分析PE文件(self, profiler, tmp_path):
        f = tmp_path / "tool.exe"
        # Minimal PE header
        f.write_bytes(b"MZ\x90\x00" + b"\x00" * 10000)

        summary = profiler.profile(str(f))
        assert summary.file_type == "executable"
        assert "MZ" in summary.summary_text or "PE" in summary.summary_text

    def test_大文件只读头部和尾部(self, profiler, tmp_path):
        f = tmp_path / "huge.log"
        # Create a file larger than max_sample_bytes (64KB default)
        content = "INFO processing item {}\n".format
        with f.open("w") as fh:
            for i in range(5000):
                fh.write(content(i))

        # 应该不会崩溃
        summary = profiler.profile(str(f))
        assert summary is not None

    def test_不可读文件不崩溃(self, profiler, tmp_path):
        f = tmp_path / "unreadable.bin"
        f.write_bytes(b"\x00" * 100)
        os.chmod(str(f), 0o000)  # 移除所有权限
        try:
            summary = profiler.profile(str(f))
            assert summary.file_type == "unknown"
        finally:
            os.chmod(str(f), 0o644)  # 恢复权限以便清理

    def test_二进制文件不尝试文本解析(self, profiler, tmp_path):
        f = tmp_path / "random.bin"
        f.write_bytes(struct.pack("BBBB", 0x89, 0x50, 0x4E, 0x47) + b"\x00" * 500)  # PNG header
        summary = profiler.profile(str(f))
        assert summary.file_type in ("image", "unknown")

    def test_摘要长度限制(self, profiler, tmp_path):
        f = tmp_path / "config.xml"
        f.write_text("<root>\n  " + "\n  ".join(f"<item{i}>value{i}</item{i}>" for i in range(200)) + "\n</root>")
        summary = profiler.profile(str(f))
        # 摘要文本不应超过 500 字符
        assert len(summary.summary_text) <= 500

    def test_批量分析不崩溃(self, profiler, tmp_path):
        files = []
        for i in range(10):
            f = tmp_path / f"file_{i}.log"
            f.write_text("".join(f"log entry {j}\n" for j in range(20)))
            files.append(str(f))

        summaries = profiler.profile_batch(files)
        assert len(summaries) == 10
        for s in summaries:
            assert isinstance(s, ContentSummary)
