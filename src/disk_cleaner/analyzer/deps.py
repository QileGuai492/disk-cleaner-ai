"""文件依赖分析——PE 导入表解析 + DLL 反向索引"""

import os
import struct
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PEImports:
    """PE 文件导入信息"""

    path: str
    dll_imports: list[str] = field(default_factory=list)
    is_pe: bool = False
    parse_error: Optional[str] = None


@dataclass
class DependencyReport:
    """文件依赖分析报告"""

    dll_name: str
    referrers: list[str] = field(default_factory=list)

    @property
    def referrer_count(self) -> int:
        # 只统计 exe 引用者
        exe_refs = [r for r in self.referrers if r.lower().endswith(".exe")]
        return len(exe_refs)

    @property
    def should_keep(self) -> bool:
        """是否应保留（被 exe 引用）"""
        return self.referrer_count > 0


class DependencyAnalyzer:
    """文件依赖分析器——PE 导入表解析 + 反向索引"""

    def __init__(self):
        self.imports: dict[str, PEImports] = {}  # path → PEImports
        self._reverse_index: dict[str, set[str]] = defaultdict(set)  # DLL → set of importer paths

    def scan_directory(self, directory: str, max_files: int = 1000) -> None:
        """扫描目录中的 PE 文件，建立依赖关系（最多扫描 max_files 个文件）"""
        count = 0
        for root, _, files in os.walk(directory):
            for fname in files:
                if count >= max_files:
                    return
                count += 1
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                # 只解析 PE 文件（exe/dll/sys/ocx）
                if ext not in (".exe", ".dll", ".sys", ".ocx"):
                    continue
                self.scan_imports(fpath)

    def scan_imports(self, path: str) -> list[PEImports]:
        """解析单个 PE 文件的导入表"""
        pe_imports = self._parse_pe_imports(path)
        if pe_imports and pe_imports.is_pe:
            self.imports[path] = pe_imports
            # 建立反向索引
            for dll in pe_imports.dll_imports:
                self._reverse_index[dll.lower()].add(path)
            return [pe_imports]
        return []

    def get_referrers(self, dll_name: str) -> list[str]:
        """查询哪些文件引用了指定的 DLL"""
        return list(self._reverse_index.get(dll_name.lower(), set()))

    def analyze(self, target: str) -> DependencyReport:
        """分析指定文件的依赖情况"""
        dll_name = os.path.basename(target)
        referrers = self.get_referrers(dll_name)
        return DependencyReport(dll_name=dll_name, referrers=list(referrers))

    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            "pe_files": len(self.imports),
            "unique_imports": len(self._reverse_index),
            "reverse_index_entries": sum(len(v) for v in self._reverse_index.values()),
        }

    def export_to_db(self, db_path: str) -> None:
        """导出到 SQLite 数据库"""
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS pe_imports (
                importer_path TEXT NOT NULL,
                imported_dll TEXT NOT NULL,
                PRIMARY KEY (importer_path, imported_dll)
            )"""
        )
        rows = [
            (importer, dll)
            for importer, pe in self.imports.items()
            for dll in pe.dll_imports
        ]
        conn.executemany(
            "INSERT OR REPLACE INTO pe_imports VALUES (?, ?)", rows
        )
        conn.commit()
        conn.close()

    def _parse_pe_imports(self, path: str) -> Optional[PEImports]:
        """解析 PE 文件导入表（真实 Import Directory，失败时回退字符串扫描）。"""
        try:
            with open(path, "rb") as f:
                data = f.read(32 * 1024 * 1024)
            if len(data) < 64 or data[:2] != b"MZ":
                return PEImports(path=path)

            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return PEImports(path=path)

            coff = data[pe_offset + 4:pe_offset + 24]
            if len(coff) < 20:
                return PEImports(path=path)
            num_sections = struct.unpack_from("<H", coff, 2)[0]
            optional_size = struct.unpack_from("<H", coff, 16)[0]
            optional_start = pe_offset + 24
            if optional_start + 2 > len(data):
                return self._fallback_imports(path, "可选头越界")
            optional_magic = struct.unpack_from("<H", data, optional_start)[0]

            # PE32: data directories 从可选头 +96 开始；PE32+: +112
            dirs_start = optional_start + (112 if optional_magic == 0x20B else 96)
            if dirs_start + 16 > len(data):
                return self._fallback_imports(path, "可选头越界")

            import_rva, _import_size = struct.unpack_from("<II", data, dirs_start + 8)
            if import_rva == 0:
                return self._fallback_imports(path, "无导入表")

            sections = []
            section_start = optional_start + optional_size
            for index in range(min(num_sections, 96)):
                offset = section_start + index * 40
                if offset + 40 > len(data):
                    break
                virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                    "<IIII", data, offset + 8
                )
                sections.append((virtual_address, max(virtual_size, raw_size), raw_pointer))

            def rva_to_offset(rva: int) -> Optional[int]:
                for virtual_address, size, raw_pointer in sections:
                    if virtual_address <= rva < virtual_address + max(size, 1):
                        return raw_pointer + (rva - virtual_address)
                return None

            descriptor_offset = rva_to_offset(import_rva)
            if descriptor_offset is None:
                return self._fallback_imports(path, "导入表 RVA 无法映射")

            dlls: list[str] = []
            for index in range(100):
                offset = descriptor_offset + index * 20
                if offset + 20 > len(data):
                    break
                name_rva = struct.unpack_from("<I", data, offset + 12)[0]
                if name_rva == 0:
                    break
                name_offset = rva_to_offset(name_rva)
                if name_offset is None or name_offset >= len(data):
                    continue
                end = data.find(b"\x00", name_offset, min(name_offset + 260, len(data)))
                if end < 0:
                    continue
                name = data[name_offset:end].decode("ascii", errors="ignore").lower()
                if name.endswith(".dll") and name not in dlls:
                    dlls.append(name)

            if not dlls:
                return self._fallback_imports(path, "导入表为空")
            return PEImports(path=path, is_pe=True, dll_imports=dlls[:200])
        except Exception as e:
            return PEImports(path=path, parse_error=str(e))

    def _fallback_imports(self, path: str, reason: str) -> PEImports:
        return PEImports(
            path=path,
            is_pe=True,
            dll_imports=self._extract_dll_names_from_file(path),
            parse_error=reason,
        )

    def _extract_dll_names_from_file(self, path: str) -> list[str]:
        """从 PE 文件中提取 DLL 名称（简化：扫描字符串中的 .dll 引用）"""
        dlls: list[str] = []
        try:
            with open(path, "rb") as f:
                data = f.read(1024 * 1024)  # 读 1MB
                # 查找所有符合 DLL 命名模式的 ASCII 字符串
                import re

                dll_pattern = re.compile(rb"([a-zA-Z_][\w-]{0,30}\.dll)", re.IGNORECASE)
                found = set()
                for match in dll_pattern.finditer(data):
                    name = match.group(1).decode("ascii", errors="ignore").lower()
                    # 过滤掉明显的误报
                    if name not in found and len(name) >= 6:
                        found.add(name)
                        dlls.append(name)
        except Exception:
            pass
        return dlls[:100]


def get_dependency_report(path: str) -> DependencyReport:
    """便捷函数：快速获取单个文件的依赖报告"""
    directory = os.path.dirname(path) or "."
    if not os.path.exists(directory):
        return DependencyReport(dll_name=os.path.basename(path))
    analyzer = DependencyAnalyzer()
    analyzer.scan_directory(directory)
    return analyzer.analyze(path)
