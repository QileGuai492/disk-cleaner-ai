"""清理安全策略——所有删除/搬迁之前的独立闸门。

AI 和规则只能给出“建议”，是否允许真正动文件由这里决定。
"""

from __future__ import annotations

import os
import stat as stat_module
from dataclasses import dataclass


@dataclass(frozen=True)
class SafetyDecision:
    """单个路径的安全判定结果。"""

    allowed: bool
    reason: str = ""


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _is_within(path: str, root: str) -> bool:
    """判断 path 是否在 root 目录之内（含 root 本身）。"""
    try:
        return os.path.commonpath([_norm(path), _norm(root)]) == _norm(root)
    except ValueError:
        # 不同盘符 / UNC 与本地路径
        return False


class SafetyPolicy:
    """硬编码的保护规则，避免误删系统文件和用户关键目录。"""

    def __init__(self, *, allow_system: bool = False, extra_protected: list[str] | None = None):
        self.allow_system = allow_system
        self._protected_trees: list[str] = []
        self._protected_exact: list[str] = []
        self._protected_files: set[str] = set()
        self._protected_extensions: set[str] = set()
        self._build_defaults()
        if extra_protected:
            self._protected_trees.extend(extra_protected)

    def _build_defaults(self) -> None:
        home = os.path.expanduser("~")
        if os.name == "nt":
            drive = (os.environ.get("SystemDrive") or "C:") + "\\"
            windows = os.environ.get("SystemRoot") or os.path.join(drive, "Windows")
            program_files = os.environ.get("ProgramFiles") or os.path.join(drive, "Program Files")
            program_files_x86 = os.environ.get("ProgramFiles(x86)") or os.path.join(
                drive, "Program Files (x86)"
            )
            program_data = os.environ.get("ProgramData") or os.path.join(drive, "ProgramData")

            self._protected_trees = [
                windows,
                program_files,
                program_files_x86,
                program_data,
                os.path.join(drive, "$Recycle.Bin"),
                os.path.join(drive, "System Volume Information"),
                os.path.join(drive, "Recovery"),
            ]
            self._protected_exact = [
                drive,
                home,
                os.path.join(home, "Desktop"),
                os.path.join(home, "Documents"),
                os.path.join(home, "Downloads"),
            ]
            self._protected_files = {
                "pagefile.sys",
                "hiberfil.sys",
                "swapfile.sys",
                "bootmgr",
                "bootnxt",
                "ntldr",
                "boot.ini",
                "ntdetect.com",
            }
            self._protected_extensions = {".sys", ".drv", ".efi", ".boot"}
        else:
            # 非 Windows 平台也给出保守默认值，避免测试/开发环境误删。
            self._protected_trees = [
                "/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys",
            ]
            self._protected_exact = ["/", home]
            self._protected_files = {"passwd", "shadow", "sudoers"}
            self._protected_extensions = {".ko"}

    def validate(self, path: str, scan_root: str | None = None) -> SafetyDecision:
        """校验一个路径是否允许清理/搬迁。"""
        if not path or not str(path).strip():
            return SafetyDecision(False, "空路径")

        absolute = os.path.abspath(str(path))
        try:
            real = os.path.realpath(absolute)
        except OSError:
            real = absolute

        if not self.allow_system:
            for root in self._protected_trees:
                if _is_within(real, root):
                    return SafetyDecision(False, f"受保护的系统目录：{root}")

            for exact in self._protected_exact:
                if _norm(real) == _norm(exact):
                    return SafetyDecision(False, f"受保护的关键目录：{exact}")

            name = os.path.basename(real).lower()
            if name in self._protected_files:
                return SafetyDecision(False, f"受保护的系统文件：{name}")

            ext = os.path.splitext(real)[1].lower()
            if ext in self._protected_extensions:
                return SafetyDecision(False, f"受保护的文件类型：{ext}")

            # 不跟随链接/联接，避免通过 junction 删到目标盘
            try:
                if os.path.islink(absolute):
                    return SafetyDecision(False, "符号链接/Junction 不允许直接清理")
                st = os.lstat(absolute)
                attrs = getattr(st, "st_file_attributes", 0)
                reparse = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                if attrs & reparse:
                    return SafetyDecision(False, "重解析点（Junction/Symlink）不允许直接清理")
            except OSError:
                # 文件不存在时交给执行器报告；安全策略不额外拦截
                pass

        if scan_root:
            if not _is_within(real, scan_root):
                return SafetyDecision(False, "路径不在本次扫描根目录内")

        return SafetyDecision(True, "")

    def validate_many(self, paths: list[str], scan_root: str | None = None) -> list[SafetyDecision]:
        return [self.validate(p, scan_root) for p in paths]
