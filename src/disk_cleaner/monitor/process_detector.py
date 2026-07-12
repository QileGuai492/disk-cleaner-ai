"""进程关联检测——发现文件时找出创建者进程"""

import os
from typing import Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class ProcessDetector:
    """检测文件与进程的关联"""

    @staticmethod
    def find_file_owner(file_path: str, timeout: float = 1.0) -> Optional[dict]:
        """查找正在使用指定文件的进程（带超时保护）"""
        if not HAS_PSUTIL:
            return None

        abs_path = os.path.abspath(file_path)
        # 只搜索有打开文件且非系统关键进程
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                # 快速跳过：只检查非系统进程
                pname = (proc.info["name"] or "").lower()
                if pname in ("system", "system idle process", "registry"):
                    continue
                # 只对有文件操作的进程类型做详细检查
                open_files = proc.open_files()
                for f in open_files:
                    if abs_path in f.path or f.path in abs_path:
                        return {
                            "pid": proc.info["pid"],
                            "name": proc.info["name"],
                            "exe": proc.info["exe"],
                        }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                pass
            except Exception:
                pass
        return None

    @staticmethod
    def find_large_processes(min_memory_mb: int = 500) -> list[dict]:
        """查找内存占用大的进程"""
        if not HAS_PSUTIL:
            return []

        results = []
        for proc in psutil.process_iter(["pid", "name", "memory_info", "exe"]):
            try:
                mem = proc.info["memory_info"]
                if mem and mem.rss > min_memory_mb * 1024 * 1024:
                    results.append({
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "exe": proc.info["exe"],
                        "memory_mb": round(mem.rss / (1024 * 1024), 1),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        results.sort(key=lambda p: p["memory_mb"], reverse=True)
        return results[:20]

    @staticmethod
    def check_process_exists(process_name: str) -> bool:
        """检查指定名称的进程是否在运行"""
        if not HAS_PSUTIL:
            return False
        name_lower = process_name.lower()
        for proc in psutil.process_iter(["name"]):
            try:
                if proc.info["name"] and proc.info["name"].lower() == name_lower:
                    return True
            except psutil.NoSuchProcess:
                pass
        return False

    @staticmethod
    def is_system_process(pid: int) -> bool:
        """判断进程是否是系统关键进程"""
        system_processes = {
            "system", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
        }
        try:
            proc = psutil.Process(pid)
            return proc.name().lower() in system_processes
        except Exception:
            return False
