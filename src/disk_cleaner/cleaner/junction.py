"""NTFS Junction 管理器——创建/删除/验证目录联接"""

import os
import shutil
import stat as stat_module
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
    def _create_link(source: Path, target: Path) -> tuple[bool, str]:
        """只创建链接，不移动数据。"""
        if os.name != "nt":
            return False, "当前平台不支持 NTFS Junction"
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(source), str(target)],
            capture_output=True,
            text=True,
            shell=False,
        )
        if result.returncode == 0:
            return True, ""
        message = (result.stderr or result.stdout or "").strip()
        return False, message or f"mklink 退出码 {result.returncode}"

    @staticmethod
    def create(source: str, target: str) -> JunctionResult:
        """在 source 位置创建 Junction，指向 target。

        source 可以是空目录（会被替换为链接）；非空目录不会被自动合并，
        请使用 relocate_directory 完成“移动 + 建链 + 失败回滚”。
        """
        source_path = Path(source)
        target_path = Path(target)

        if not target_path.exists():
            return JunctionResult(
                source=str(source_path), target=str(target_path),
                action="failed", success=False, error="目标目录不存在",
            )
        if not target_path.is_dir():
            return JunctionResult(
                source=str(source_path), target=str(target_path),
                action="failed", success=False, error="目标不是目录",
            )

        removed_empty_source = False
        if source_path.exists():
            if JunctionManager.is_junction(str(source_path)):
                return JunctionResult(
                    source=str(source_path), target=str(target_path),
                    action="failed", success=False, error="路径已是 Junction",
                )
            if not source_path.is_dir():
                return JunctionResult(
                    source=str(source_path), target=str(target_path),
                    action="failed", success=False,
                    error="源路径是文件，不能创建目录 Junction",
                )
            try:
                if any(source_path.iterdir()):
                    return JunctionResult(
                        source=str(source_path), target=str(target_path),
                        action="failed", success=False,
                        error="源目录非空；为避免数据丢失，请使用 relocate_directory",
                    )
            except OSError as e:
                return JunctionResult(
                    source=str(source_path), target=str(target_path),
                    action="failed", success=False, error=f"无法读取源目录: {e}",
                )
            try:
                source_path.rmdir()
                removed_empty_source = True
            except OSError as e:
                return JunctionResult(
                    source=str(source_path), target=str(target_path),
                    action="failed", success=False, error=f"无法移除空源目录: {e}",
                )

        try:
            ok, error = JunctionManager._create_link(source_path, target_path)
        except Exception as e:
            ok, error = False, str(e)

        if ok:
            return JunctionResult(
                source=str(source_path), target=str(target_path),
                action="created", success=True,
            )

        # 创建失败：恢复被移除的空目录，保持原状
        if removed_empty_source:
            try:
                source_path.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
        return JunctionResult(
            source=str(source_path), target=str(target_path),
            action="failed", success=False, error=error,
        )

    @staticmethod
    def remove(junction_path: str) -> JunctionResult:
        """删除 Junction（不删除目标内容）"""
        path = Path(junction_path)
        if not os.path.lexists(str(path)):
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
        """检查路径是否是 NTFS Junction / 重解析点。"""
        try:
            st = os.lstat(path)
        except OSError:
            return False
        attrs = getattr(st, "st_file_attributes", 0)
        reparse = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if not (attrs & reparse) and not os.path.islink(path):
            return False
        return stat_module.S_ISDIR(st.st_mode) or os.path.islink(path)

    @staticmethod
    def relocate_directory(
        source: str,
        target_base: str,
        auto_junction: bool = True,
    ) -> JunctionResult:
        """将目录搬迁到 target_base 下，可选创建 Junction。

        采用“移动 → 建链 → 失败回滚”的顺序；任何一步失败都会把目录移回原位置。
        """
        source_path = Path(source)
        if not source_path.exists():
            return JunctionResult(
                source=str(source_path), target="",
                action="failed", success=False, error="源目录不存在",
            )
        if not source_path.is_dir():
            return JunctionResult(
                source=str(source_path), target="",
                action="failed", success=False, error="源路径不是目录",
            )
        if not source_path.name:
            return JunctionResult(
                source=str(source_path), target="",
                action="failed", success=False, error="不能搬迁盘符根目录",
            )

        target_base_path = Path(target_base)
        target_base_path.mkdir(parents=True, exist_ok=True)
        target_path = target_base_path / source_path.name

        if target_path.exists():
            return JunctionResult(
                source=str(source_path), target=str(target_path),
                action="failed", success=False, error="目标路径已存在，请先确认",
            )
        try:
            if os.path.commonpath([
                os.path.abspath(str(target_path)),
                os.path.abspath(str(source_path)),
            ]) == os.path.abspath(str(source_path)):
                return JunctionResult(
                    source=str(source_path), target=str(target_path),
                    action="failed", success=False, error="目标路径不能位于源目录内部",
                )
        except ValueError:
            pass

        try:
            shutil.move(str(source_path), str(target_path))
        except Exception as e:
            return JunctionResult(
                source=str(source_path), target=str(target_path),
                action="failed", success=False, error=f"移动失败: {e}",
            )

        if not auto_junction:
            return JunctionResult(
                source=str(source_path), target=str(target_path),
                action="relocated", success=True,
            )

        try:
            ok, error = JunctionManager._create_link(source_path, target_path)
        except Exception as e:
            ok, error = False, str(e)

        if ok:
            return JunctionResult(
                source=str(source_path), target=str(target_path),
                action="created", success=True,
            )

        # 回滚：把已移动的目录搬回原位置
        try:
            if os.path.lexists(str(source_path)):
                # 只允许清掉空目录/残留链接，绝不递归删除
                os.rmdir(str(source_path))
            shutil.move(str(target_path), str(source_path))
            rollback = "已回滚"
        except Exception as rollback_error:
            rollback = (
                f"回滚失败，请手动将 {target_path} 移回 {source_path}：{rollback_error}"
            )
        return JunctionResult(
            source=str(source_path), target=str(target_path),
            action="failed", success=False,
            error=f"{error}；{rollback}",
        )
