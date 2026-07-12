"""NTFS Junction 管理器——创建/删除/验证目录联接"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class JunctionResult:
    """Junction 操作结果"""

    source: str  # 原始路径
    target: str  # Junction 目标
    action: str  # created / removed / verified / failed
    success: bool
    error: Optional[str] = None


class JunctionManager:
    """NTFS Junction（目录联接）管理器"""

    @staticmethod
    def create(source: str, target: str) -> JunctionResult:
        """在 source 位置创建 Junction，指向 target

        Args:
            source: Junction 的创建位置（原始文件路径）
            target: Junction 指向的实际位置

        Returns:
            JunctionResult
        """
        source_path = Path(source)
        target_path = Path(target)

        if not target_path.exists():
            return JunctionResult(
                source=str(source_path),
                target=str(target_path),
                action="failed",
                success=False,
                error="目标目录不存在",
            )

        try:
            # 如果 source 存在且不是 junction，先备份
            if source_path.exists():
                if JunctionManager.is_junction(str(source_path)):
                    return JunctionResult(
                        source=str(source_path),
                        target=str(target_path),
                        action="failed",
                        success=False,
                        error="路径已是 Junction",
                    )
                # 不是 junction，但是有文件——移动到 target
                shutil.move(str(source_path), str(target_path))

            # 创建 Junction: mklink /J <link> <target>
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(source_path), str(target_path)],
                capture_output=True,
                text=True,
                shell=False,
            )
            if result.returncode == 0:
                return JunctionResult(
                    source=str(source_path),
                    target=str(target_path),
                    action="created",
                    success=True,
                )
            return JunctionResult(
                source=str(source_path),
                target=str(target_path),
                action="failed",
                success=False,
                error=result.stderr.strip(),
            )
        except Exception as e:
            return JunctionResult(
                source=str(source_path),
                target=str(target_path),
                action="failed",
                success=False,
                error=str(e),
            )

    @staticmethod
    def remove(junction_path: str) -> JunctionResult:
        """删除 Junction（不删除目标内容）"""
        path = Path(junction_path)
        if not path.exists():
            return JunctionResult(
                source=str(path), target="", action="failed",
                success=False, error="路径不存在",
            )
        if not JunctionManager.is_junction(str(path)):
            return JunctionResult(
                source=str(path), target="", action="failed",
                success=False, error="不是 Junction",
            )

        try:
            # rmdir 可以安全删除 Junction（不会删除目标内容）
            subprocess.run(
                ["cmd", "/c", "rmdir", str(path)],
                capture_output=True,
                check=True,
            )
            return JunctionResult(
                source=str(path), target="", action="removed", success=True,
            )
        except Exception as e:
            return JunctionResult(
                source=str(path), target="", action="failed",
                success=False, error=str(e),
            )

    @staticmethod
    def is_junction(path: str) -> bool:
        """检查路径是否是 NTFS Junction"""
        try:
            path_obj = Path(path)
            if not path_obj.exists():
                return False
            # Junction 的 stat 显示为目录但 `os.path.islink` 检查 reparse point
            # Windows: 检查 reparse point 属性
            import stat as st

            file_stat = path_obj.stat()
            # ST_REPARSE_TAG = 0x20000000 (not in Python's stat module directly)
            # Use os.path.islink check for symlinks, then directory check for junctions
            return path_obj.is_dir() and bool(
                os.path.islink(path) or path_obj.stat().st_file_attributes & 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
                if hasattr(path_obj.stat(), "st_file_attributes")
                else False
            )
        except Exception:
            return False

    @staticmethod
    def relocate_directory(
        source: str,
        target_base: str,
        auto_junction: bool = True,
    ) -> JunctionResult:
        """将目录搬迁到 target_base 下，可选创建 Junction

        Args:
            source: 要搬迁的目录
            target_base: 目标基础路径（如 D:\\Relocated）
            auto_junction: 是否自动在原位置创建 Junction

        Returns:
            JunctionResult
        """
        source_path = Path(source)
        if not source_path.exists():
            return JunctionResult(
                source=str(source_path), target="",
                action="failed", success=False, error="源目录不存在",
            )

        target_base_path = Path(target_base)
        target_base_path.mkdir(parents=True, exist_ok=True)

        # 构建目标路径
        rel_name = source_path.name
        target_path = target_base_path / rel_name

        try:
            # 移动目录
            shutil.move(str(source_path), str(target_path))

            if auto_junction:
                return JunctionManager.create(source, str(target_path))
            return JunctionResult(
                source=str(source_path),
                target=str(target_path),
                action="relocated",
                success=True,
            )
        except Exception as e:
            return JunctionResult(
                source=str(source_path),
                target=str(target_path),
                action="failed",
                success=False,
                error=str(e),
            )
