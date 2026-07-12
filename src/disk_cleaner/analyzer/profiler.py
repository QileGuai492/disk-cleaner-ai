"""文件内容摘要提取器——本地采样，只发摘要不上传内容"""

import json
import os
import re
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


class FileType(Enum):
    TEXT_LOG = "text_log"
    CONFIG = "config"
    DATABASE = "database"
    EXECUTABLE = "executable"
    ARCHIVE = "archive"
    IMAGE = "image"
    VIDEO = "video"
    UNKNOWN = "unknown"


@dataclass
class ContentSummary:
    """文件内容摘要"""

    file_type: str
    summary_text: str  # 自然语言摘要，< 500 字符
    sensitive_detected: bool = False
    sensitive_keys: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_ai_dict(self) -> dict:
        """转为 AI prompt 中可用的格式"""
        result = {"file_type": self.file_type, "has_sensitive_keywords": self.sensitive_detected}
        result.update(self.extra)
        return result


# 文件类型特征
LOG_EXTENSIONS = {".log"}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".xml", ".ini", ".conf", ".cfg", ".toml", ".properties"}
DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".mdb"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp"}
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".webm"}

# Magic bytes 识别
MAGIC_PE = b"MZ"
MAGIC_ZIP = b"PK\x03\x04"
MAGIC_SQLITE = b"SQLite format 3\x00"
MAGIC_PNG = b"\x89PNG"
MAGIC_JPEG = b"\xff\xd8\xff"
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_PDF = b"%PDF"
MAGIC_ELF = b"\x7fELF"

# 敏感 key 关键词
SENSITIVE_KEYWORDS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "access_key", "auth", "credential", "pwd",
}


class ContentProfiler:
    """文件内容分析器——本地读取，提取结构化摘要"""

    def __init__(self, max_sample_bytes: int = 65536):
        self.max_sample_bytes = max_sample_bytes  # 默认读 64KB

    @classmethod
    def identify_type(cls, path: str) -> FileType:
        """根据扩展名和 magic bytes 识别文件类型"""
        ext = Path(path).suffix.lower()
        name = Path(path).name.lower()

        # 扩展名优先
        if ext in LOG_EXTENSIONS:
            return FileType.TEXT_LOG
        if ext in CONFIG_EXTENSIONS:
            return FileType.CONFIG
        if ext in DATABASE_EXTENSIONS:
            return FileType.DATABASE
        if ext in ARCHIVE_EXTENSIONS:
            return FileType.ARCHIVE
        if ext in IMAGE_EXTENSIONS:
            return FileType.IMAGE
        if ext in VIDEO_EXTENSIONS:
            return FileType.VIDEO

        # 无扩展名或未知扩展名，检查 magic bytes
        try:
            with open(path, "rb") as f:
                header = f.read(16)
        except Exception:
            return FileType.UNKNOWN

        if header[:2] == MAGIC_PE:
            return FileType.EXECUTABLE
        if header[:4] == MAGIC_ZIP:
            return FileType.ARCHIVE
        if header[:16] == MAGIC_SQLITE:
            return FileType.DATABASE
        if header[:4] == MAGIC_PNG or header[:3] == MAGIC_JPEG:
            return FileType.IMAGE
        if header[:3] == MAGIC_GZIP:
            return FileType.ARCHIVE
        if header[:4] == MAGIC_ELF:
            return FileType.EXECUTABLE

        return FileType.UNKNOWN

    def profile(self, path: str) -> ContentSummary:
        """分析单个文件，返回内容摘要"""
        file_type = self.identify_type(path)
        file_size = os.path.getsize(path) if os.path.exists(path) else 0

        try:
            if file_type == FileType.TEXT_LOG:
                return self._profile_log(path, file_size)
            elif file_type == FileType.CONFIG:
                return self._profile_config(path, file_size)
            elif file_type == FileType.DATABASE:
                return self._profile_database(path, file_size)
            elif file_type == FileType.EXECUTABLE:
                return self._profile_executable(path)
            elif file_type == FileType.ARCHIVE:
                return self._profile_archive(path, file_size)
            elif file_type in (FileType.IMAGE, FileType.VIDEO):
                return self._profile_media(path, file_size, file_type.value)
            else:
                return self._profile_unknown(path)
        except Exception as e:
            return ContentSummary(
                file_type="unknown",
                summary_text=f"无法分析: {str(e)[:100]}",
            )

    def profile_batch(self, paths: list[str]) -> list[ContentSummary]:
        """批量分析"""
        return [self.profile(p) for p in paths]

    def _read_sample(self, path: str, file_size: int) -> tuple[str, str]:
        """读取文件头尾样本，返回 (head_text, tail_text)"""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                if file_size <= self.max_sample_bytes:
                    content = f.read()
                    return content, ""
                else:
                    head = f.read(self.max_sample_bytes)
                    # 读尾部
                    f.seek(max(0, file_size - 4096))
                    tail = f.read(4096)
                    return head, tail
        except Exception:
            return "", ""

    def _read_binary_sample(self, path: str) -> bytes:
        """读取二进制文件头部"""
        try:
            with open(path, "rb") as f:
                return f.read(min(256, self.max_sample_bytes))
        except Exception:
            return b""

    def _profile_log(self, path: str, file_size: int) -> ContentSummary:
        """分析日志文件"""
        head, tail = self._read_sample(path, file_size)
        content = head + tail
        lines = content.split("\n")
        total_lines = len(lines)

        # 统计关键词
        error_count = sum(1 for l in lines if "ERROR" in l.upper() or "FATAL" in l.upper())
        warn_count = sum(1 for l in lines if "WARN" in l.upper())

        # 提取时间戳范围
        timestamps = re.findall(r"(\d{4}-\d{2}-\d{2})", content)
        time_span = ""
        if len(timestamps) >= 2:
            time_span = f"时间跨度 {timestamps[0]} 至 {timestamps[-1]}"
        elif timestamps:
            time_span = f"含时间戳 {timestamps[0]}"

        parts = [f"文本日志，采样 {total_lines} 行"]
        if time_span:
            parts.append(time_span)
        if error_count:
            parts.append(f"含 {error_count} 条 ERROR/FATAL")
        if warn_count:
            parts.append(f"含 {warn_count} 条 WARN")

        # 提取最频繁的消息模板
        if error_count > 0:
            error_lines = [l for l in lines if "ERROR" in l.upper()]
            sample_error = error_lines[0][:120] if error_lines else ""
            if sample_error:
                parts.append(f"示例错误: {sample_error}")

        summary_text = "，".join(parts)[:500]
        return ContentSummary(file_type="text_log", summary_text=summary_text)

    def _profile_config(self, path: str, file_size: int) -> ContentSummary:
        """分析配置文件——提取 key 名称但不提取值"""
        head, tail = self._read_sample(path, file_size)
        content = head + (tail if tail else "")

        sensitive_detected = False
        sensitive_keys: list[str] = []
        keys: list[str] = []

        # 尝试 JSON 解析
        if path.endswith(".json"):
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    keys = list(data.keys())
                    for k in keys:
                        if any(sk in k.lower() for sk in SENSITIVE_KEYWORDS):
                            sensitive_keys.append(k)
                            sensitive_detected = True
            except json.JSONDecodeError:
                pass

        # YAML/INI 简单解析：提取 key 名称
        if not keys:
            key_pattern = re.findall(r"^\s*([a-zA-Z_][\w.]*)\s*[:=]", content, re.MULTILINE)
            keys = list(set(key_pattern))[:20]
            for k in keys:
                if any(sk in k.lower() for sk in SENSITIVE_KEYWORDS):
                    sensitive_keys.append(k)
                    sensitive_detected = True

        file_label = Path(path).suffix.upper().lstrip(".")
        parts = [f"{file_label} 配置，{len(keys)} 个字段"]
        if keys:
            parts.append(f"字段: {', '.join(keys[:10])}")
        if sensitive_detected:
            parts.append(f"含 {len(sensitive_keys)} 个敏感字段({','.join(sensitive_keys[:5])})")

        summary_text = "，".join(parts)[:500]
        return ContentSummary(
            file_type="config",
            summary_text=summary_text,
            sensitive_detected=sensitive_detected,
            sensitive_keys=sensitive_keys,
            extra={"keys": keys, "field_count": len(keys)},
        )

    def _profile_database(self, path: str, file_size: int) -> ContentSummary:
        """分析数据库文件"""
        try:
            import sqlite3
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            # 估算行数
            row_counts = {}
            for table in tables[:10]:
                try:
                    count = conn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]
                    row_counts[table] = count
                except Exception:
                    row_counts[table] = -1
            conn.close()

            parts = [f"SQLite DB，{len(tables)} 张表: {', '.join(tables[:8])}"]
            for table, count in row_counts.items():
                if count >= 0:
                    parts.append(f"表 {table} 约 {count} 行")
            summary_text = "，".join(parts)[:500]
            return ContentSummary(
                file_type="sqlite",
                summary_text=summary_text,
                extra={"tables": tables, "row_counts": row_counts},
            )
        except Exception:
            return ContentSummary(file_type="database", summary_text="数据库文件（无法读取结构）")

    def _profile_executable(self, path: str) -> ContentSummary:
        """分析可执行文件"""
        data = self._read_binary_sample(path)
        if data[:2] == b"MZ":
            has_pe = b"PE\x00\x00" in data
            return ContentSummary(
                file_type="executable",
                summary_text=f"PE 可执行文件{'（含 PE 头）' if has_pe else ''}，无数字签名信息",
            )
        elif data[:4] == b"\x7fELF":
            return ContentSummary(file_type="executable", summary_text="ELF 可执行文件")
        return ContentSummary(file_type="executable", summary_text="可执行文件")

    def _profile_archive(self, path: str, file_size: int) -> ContentSummary:
        """分析归档文件"""
        data = self._read_binary_sample(path)
        archive_type = "未知归档"
        if data[:4] == MAGIC_ZIP:
            archive_type = "ZIP"
        elif data[:3] == MAGIC_GZIP:
            archive_type = "GZip"

        parts = [f"{archive_type} 压缩包"]
        if file_size > 0:
            parts.append(f"压缩大小 {file_size / (1024**2):.1f} MB")
        summary_text = "，".join(parts)[:500]
        return ContentSummary(file_type="archive", summary_text=summary_text)

    def _profile_media(self, path: str, file_size: int, media_type: str) -> ContentSummary:
        """分析图片/视频"""
        size_mb = file_size / (1024**2) if file_size > 0 else 0
        parts = [f"{'图片' if media_type == 'image' else '视频'}文件"]
        if size_mb > 0:
            parts.append(f"{size_mb:.1f} MB")
        summary_text = "，".join(parts)[:500]
        return ContentSummary(file_type=media_type, summary_text=summary_text)

    def _profile_unknown(self, path: str) -> ContentSummary:
        """分析未知文件"""
        data = self._read_binary_sample(path)
        if not data:
            return ContentSummary(file_type="unknown", summary_text="空文件")

        # 提取可读字符串
        try:
            text = data.decode("ascii", errors="ignore")
            readable = "".join(c for c in text[:100] if c.isprintable() or c in " \t\n")
        except Exception:
            readable = ""

        # 检查熵值（简单的字节多样性判断是否加密/压缩）
        unique_bytes = len(set(data))
        entropy_hint = "高熵值（疑似加密或压缩）" if unique_bytes > 200 else ""

        hex_head = data[:16].hex(" ").upper()
        parts = [f"未知二进制格式，magic: {hex_head}"]
        if entropy_hint:
            parts.append(entropy_hint)
        if readable.strip():
            parts.append(f"可读片段: {readable.strip()[:50]}")

        summary_text = "，".join(parts)[:500]
        return ContentSummary(file_type="unknown", summary_text=summary_text)
