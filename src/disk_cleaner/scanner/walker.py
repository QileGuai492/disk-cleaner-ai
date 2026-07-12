"""目录遍历与文件信息提取"""

import heapq
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class FileInfo:
    """文件元信息"""

    path: str
    size: int  # bytes
    mtime: float  # Unix timestamp

    @property
    def extension(self) -> str:
        """提取扩展名（小写），无扩展名返回空字符串"""
        suffix = Path(self.path).suffix.lower()
        return suffix

    @property
    def size_mb(self) -> float:
        return round(self.size / (1024 * 1024), 1)

    @property
    def size_gb(self) -> float:
        return round(self.size / (1024 * 1024 * 1024), 2)

    @property
    def name(self) -> str:
        return Path(self.path).name

    @property
    def path_keywords(self) -> list[str]:
        """从路径中提取关键词"""
        parts = Path(self.path).parts
        # 跳过盘符（如 C:\）
        meaningful = [p for p in parts if p and not p.endswith(":")]
        return meaningful


def scan_directory(
    path: str,
    *,
    top_n: Optional[int] = None,
    min_size: int = 0,
    skip_symlinks: bool = False,
    recursive: bool = True,
    collect_errors: bool = False,
) -> list[FileInfo] | tuple[list[FileInfo], list[dict]]:
    """扫描目录，返回 FileInfo 列表（按大小降序）

    Args:
        path: 要扫描的目录路径
        top_n: 只返回最大的 N 个文件
        min_size: 过滤小于此大小的文件（字节）
        skip_symlinks: 是否跳过符号链接
        recursive: 是否递归扫描子目录
        collect_errors: 是否收集跳过/错误信息

    Returns:
        如果 collect_errors=False，直接返回 FileInfo 列表
        如果 collect_errors=True，返回 (FileInfo 列表, 跳過详情列表)
    """
    if not os.path.isdir(path):
        raise FileNotFoundError(f"目录不存在: {path}")

    results: list[FileInfo] = []
    skipped: list[dict] = []

    use_heap = top_n is not None

    def _scan_dir(dirpath: str) -> None:
        try:
            entries = os.scandir(dirpath)
        except PermissionError:
            skipped.append({"path": dirpath, "reason": "权限不足"})
            return
        for entry in entries:
            if not entry.is_file(follow_symlinks=not skip_symlinks):
                continue

            if skip_symlinks and entry.is_symlink():
                skipped.append({"path": entry.path, "reason": "符号链接"})
                continue

            try:
                stat = entry.stat()
            except (OSError, PermissionError):
                skipped.append({"path": entry.path, "reason": "权限不足或文件已移动"})
                continue

            if stat.st_size < min_size:
                continue

            fi = FileInfo(
                path=os.path.abspath(entry.path),
                size=stat.st_size,
                mtime=stat.st_mtime,
            )
            if use_heap:
                # 用堆保持 top N（size 为排序键，id 打破平局）
                heapq.heappush(results, (fi.size, id(fi), fi))
                while len(results) > top_n:
                    heapq.heappop(results)
            else:
                results.append(fi)

    if recursive:
        scanned_count = 0
        for dirpath, dirnames, filenames in os.walk(path, followlinks=not skip_symlinks):
            _scan_dir(dirpath)
            scanned_count += 1
            # 扫描 500 个目录后停止，防止超大目录卡死
            if scanned_count > 500:
                break
    else:
        _scan_dir(path)

    if use_heap:
        results = sorted([r[2] for r in results], key=lambda x: x.size, reverse=True)
    else:
        results.sort(key=lambda x: x.size, reverse=True)
        if top_n is not None:
            results = results[:top_n]

    if collect_errors:
        return results, skipped
    return results
