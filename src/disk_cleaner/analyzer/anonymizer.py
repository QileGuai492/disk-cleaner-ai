"""路径脱敏——发送云端前隐藏敏感信息"""

import os
import re
from pathlib import Path


class PathAnonymizer:
    """路径脱敏器"""

    BLOCKED_EXTENSIONS = {".kdbx", ".pem", ".pfx", ".env", ".key", ".p12"}

    # 需要替换的敏感目录名（中文/特殊含义）
    SENSITIVE_SEGMENTS = {
        "照片", "相册", "图片", "视频", "音乐",
        "文档", "桌面", "下载", "工作", "个人",
        "密码", "密钥", "凭证", "银行", "账户",
        "工资", "合同", "简历", "身份证",
    }

    def __init__(self, level: str = "strict"):
        """
        Args:
            level: strict（最大脱敏）/ moderate（中等）/ minimal（最小）
        """
        self.level = level

    def anonymize(self, path: str) -> str:
        """对单个路径进行脱敏"""
        if not path:
            return ""

        parts = list(Path(path).parts)
        if not parts:
            return path

        result_parts: list[str] = []

        for i, part in enumerate(parts):
            # 跳过盘符
            if part.endswith(":"):
                result_parts.append(part)
                continue

            # 替换 Users 下的用户名
            if i > 0 and parts[i - 1].lower() == "users" and self.level in ("strict", "moderate"):
                result_parts.append("<USER>")
                continue

            # strict 模式：替换所有中文和敏感英文目录名
            if self.level == "strict" and (self._is_sensitive(part) or self._contains_chinese(part)):
                result_parts.append(f"<DIR_{len(result_parts)}>")
                continue

            # moderate 模式：只替换中文
            if self.level == "moderate" and self._contains_chinese(part):
                result_parts.append(f"<DIR_{len(result_parts)}>")
                continue

            result_parts.append(part)

        if not result_parts:
            return path
        # 修复盘符拼接：Path("C:", "Users") → "C:Users"，需要 "C:\\" 才是 "C:\Users"
        if result_parts[0].endswith(":"):
            result_parts[0] = result_parts[0] + "\\"
        return str(Path(*result_parts))

    def anonymize_batch(self, paths: list[str]) -> list[str]:
        """批量脱敏"""
        # 建立全局映射，确保同一个敏感词在不同路径中替换为相同的占位符
        return [self.anonymize(p) for p in paths]

    def is_blocked_extension(self, path: str) -> bool:
        """检查文件扩展名是否在云端发送黑名单中"""
        ext = Path(path).suffix.lower()
        return ext in self.BLOCKED_EXTENSIONS

    def should_send_to_cloud(self, path: str, cloud_blocklist: list[str] | None = None) -> bool:
        """判断路径是否应该发往云端

        Args:
            path: 文件路径
            cloud_blocklist: 云端黑名单模式列表（glob）

        Returns:
            True 表示可以发送
        """
        import fnmatch

        # 扩展名黑名单
        if self.is_blocked_extension(path):
            return False

        # 路径黑名单
        if cloud_blocklist:
            for pattern in cloud_blocklist:
                normalized = path.replace("\\", "/")
                if fnmatch.fnmatch(normalized, pattern):
                    return False

        return True

    def _is_sensitive(self, segment: str) -> bool:
        """判断路径片段是否敏感"""
        for keyword in self.SENSITIVE_SEGMENTS:
            if keyword in segment:
                return True
        return False

    def _contains_chinese(self, text: str) -> bool:
        """判断是否包含中文字符"""
        return bool(re.search(r"[一-鿿]", text))
