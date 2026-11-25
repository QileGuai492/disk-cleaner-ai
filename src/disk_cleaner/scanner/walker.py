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
    skip_symlinks: bool = True,
    recursive: bool = True,
    collect_errors: bool = False,
    max_dirs: Optional[int] = 5000,
) -> list[FileInfo] | tuple[list[FileInfo], list[dict]]:
    """扫描目录，返回 FileInfo 列表（按大小降序）。

    使用单次 scandir 递归，避免 os.walk + scandir 的重复遍历；
    top_n 对全树生效，保证返回的是真正的最大 N 个文件。

    Args:
        path: 要扫描的目录路径
        top_n: 只返回最大的 N 个文件
        min_size: 过滤小于此大小的文件（字节）
        skip_symlinks: 是否跳过符号链接/Junction（默认跳过）
        recursive: 是否递归扫描子目录
        collect_errors: 是否收集跳过/错误信息
        max_dirs: 最多扫描的目录数；None 表示不限制。超出时会记录 skipped。

    Returns:
        如果 collect_errors=False，直接返回 FileInfo 列表
        如果 collect_errors=True，返回 (FileInfo 列表, 跳过详情列表)
    """
    if not os.path.isdir(path):
        raise FileNotFoundError(f"目录不存在: {path}")

    results: list[FileInfo] = []
    skipped: list[dict] = []
    heap: list[tuple[int, int, FileInfo]] = []
    counter = 0
    scanned_dirs = 0
    truncated = False

    stack = [os.path.abspath(path)]
    while stack:
        dirpath = stack.pop()
        if max_dirs is not None and scanned_dirs >= max_dirs:
            truncated = True
            break
        scanned_dirs += 1

        try:
            with os.scandir(dirpath) as entries:
                for entry in entries:
                    if skip_symlinks and entry.is_symlink():
                        skipped.append({"path": entry.path, "reason": "符号链接"})
                        continue

                    try:
                        if entry.is_dir(follow_symlinks=not skip_symlinks):
                            if recursive:
                                stack.append(entry.path)
                            continue

                        if not entry.is_file(follow_symlinks=not skip_symlinks):
                            continue
                        st = entry.stat(follow_symlinks=not skip_symlinks)
                    except (OSError, PermissionError):
                        skipped.append({"path": entry.path, "reason": "权限不足或文件已移动"})
                        continue

                    if st.st_size < min_size:
                        continue

                    fi = FileInfo(
                        path=os.path.abspath(entry.path),
                        size=st.st_size,
                        mtime=st.st_mtime,
                    )
                    counter += 1
                    if top_n is not None:
                        heapq.heappush(heap, (fi.size, counter, fi))
                        while len(heap) > top_n:
                            heapq.heappop(heap)
                    else:
                        results.append(fi)
        except PermissionError:
            skipped.append({"path": dirpath, "reason": "权限不足"})
            continue
        except OSError:
            skipped.append({"path": dirpath, "reason": "读取失败"})
            continue

    if truncated:
        skipped.append({
            "path": path,
            "reason": f"目录数量超过上限 {max_dirs}，结果可能不完整",
        })

    if top_n is not None:
        results = sorted((item[2] for item in heap), key=lambda x: x.size, reverse=True)
    else:
        results.sort(key=lambda x: x.size, reverse=True)

    if collect_errors:
        return results, skipped
    return results
