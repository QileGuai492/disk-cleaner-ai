"""清理执行器——安全删除与备份管理"""

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class CleanResult:
    """单次清理操作的结果"""

    path: str
    success: bool
    bytes_freed: int
    action: str  # deleted / moved_to_backup / skipped / failed
    backup_path: Optional[str] = None
    error: Optional[str] = None


class BackupManager:
    """安全模式——待清理文件先移到备份区，N 天后自动删除"""

    def __init__(self, backup_root: str, retention_days: int = 30):
        self.backup_root = Path(backup_root)
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days

    def create_batch(self, label: str = "") -> str:
        """创建新备份批次，返回批次 ID"""
        now = datetime.now()
        batch_id = now.strftime("%Y-%m-%d_%H-%M-%S") + f"-{now.microsecond // 1000:03d}"
        batch_dir = self.backup_root / batch_id
        batch_dir.mkdir(parents=True, exist_ok=True)

        manifest = {
            "batch_id": batch_id,
            "label": label,
            "created_at": now.isoformat(),
            "retention_days": self.retention_days,
            "expires_at": datetime.fromtimestamp(
                time.time() + self.retention_days * 86400
            ).isoformat(),
            "files": [],
        }
        (batch_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return batch_id

    def backup_file(self, file_path: str, batch_id: str) -> CleanResult:
        """将文件移到备份区，保持相对路径结构"""
        src = Path(file_path)
        if not src.exists():
            return CleanResult(
                path=file_path, success=False, bytes_freed=0,
                action="failed", error="文件不存在",
            )

        file_size = src.stat().st_size
        batch_dir = self.backup_root / batch_id

        # 保持目录结构：如 C:/Users/.../file.txt → batch_dir/C/Users/.../file.txt
        try:
            # 构建备份中的相对路径
            rel_path = str(src).replace(":", "").replace("\\", "/").lstrip("/")
            dest = batch_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)

            shutil.move(str(src), str(dest))

            # 更新 manifest
            manifest_path = batch_dir / "manifest.json"
            if manifest_path.exists():
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest["files"].append({
                    "original_path": str(src),
                    "backup_path": str(dest),
                    "size": file_size,
                    "backed_up_at": datetime.now().isoformat(),
                })
                manifest_path.write_text(
                    json.dumps(manifest, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )

            return CleanResult(
                path=file_path, success=True, bytes_freed=file_size,
                action="moved_to_backup", backup_path=str(dest),
            )
        except Exception as e:
            return CleanResult(
                path=file_path, success=False, bytes_freed=0,
                action="failed", error=str(e),
            )

    def list_batches(self) -> list[dict]:
        """列出所有备份批次"""
        batches = []
        for d in sorted(self.backup_root.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            manifest = d / "manifest.json"
            if manifest.exists():
                batches.append(json.loads(manifest.read_text(encoding="utf-8")))
        return batches

    def restore_batch(self, batch_id: str) -> list[CleanResult]:
        """恢复一个批次中的所有文件"""
        batch_dir = self.backup_root / batch_id
        manifest = batch_dir / "manifest.json"
        if not manifest.exists():
            return []

        data = json.loads(manifest.read_text(encoding="utf-8"))
        results = []
        for file_info in data.get("files", []):
            src = Path(file_info["backup_path"])
            dest = Path(file_info["original_path"])
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), str(dest))
                results.append(CleanResult(
                    path=file_info["original_path"], success=True,
                    bytes_freed=file_info["size"], action="restored",
                ))
            except Exception as e:
                results.append(CleanResult(
                    path=file_info["original_path"], success=False,
                    bytes_freed=0, action="failed", error=str(e),
                ))
        return results

    def delete_batch(self, batch_id: str) -> bool:
        """永久删除备份批次"""
        batch_dir = self.backup_root / batch_id
        if batch_dir.exists():
            shutil.rmtree(str(batch_dir))
            return True
        return False

    def prune_expired(self) -> int:
        """清理过期的备份批次，返回清理的批次数量"""
        cutoff = time.time() - self.retention_days * 86400
        count = 0
        for d in self.backup_root.iterdir():
            if not d.is_dir():
                continue
            try:
                mtime = d.stat().st_mtime
                if mtime < cutoff:
                    shutil.rmtree(str(d))
                    count += 1
            except Exception:
                pass
        return count


class CleanExecutor:
    """清理执行器——统一入口"""

    def __init__(self, backup_dir: str = "~/disk-cleaner-backup"):
        self.backup_dir = os.path.expanduser(backup_dir)
        self.backup_manager = BackupManager(self.backup_dir)
        self._keep_patterns: list[str] = []

    def add_keep_list(self, patterns: list[str]) -> None:
        """添加白名单模式（匹配的文件不会被清理）"""
        self._keep_patterns.extend(patterns)

    def _should_keep(self, path: str) -> bool:
        """检查文件是否在白名单中"""
        import fnmatch
        name = os.path.basename(path)
        for pattern in self._keep_patterns:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(name, pattern):
                return True
        return False

    def clean(
        self, file_paths: list[str], mode: str = "backup"
    ) -> list[CleanResult]:
        """执行清理操作

        Args:
            file_paths: 要清理的文件路径列表
            mode: backup（移到备份区）/ recycle（回收站）/ permanent（永久删除）

        Returns:
            每个文件的清理结果
        """
        results: list[CleanResult] = []

        batch_id = self.backup_manager.create_batch("cleanup") if mode in ("backup", "recycle") else ""

        for fp in file_paths:
            # 白名单检查
            if self._should_keep(fp):
                results.append(CleanResult(
                    path=fp, success=False, bytes_freed=0,
                    action="skipped", error="白名单保护",
                ))
                continue

            path = Path(fp)
            if not path.exists():
                results.append(CleanResult(
                    path=fp, success=False, bytes_freed=0,
                    action="failed", error="文件不存在",
                ))
                continue

            file_size = path.stat().st_size

            try:
                if mode == "backup":
                    result = self.backup_manager.backup_file(fp, batch_id)
                elif mode == "permanent":
                    os.unlink(fp)
                    result = CleanResult(
                        path=fp, success=True, bytes_freed=file_size,
                        action="permanently_deleted",
                    )
                else:
                    # recycle: 使用系统回收站
                    try:
                        import send2trash
                        send2trash.send2trash(fp)
                        result = CleanResult(
                            path=fp, success=True, bytes_freed=file_size,
                            action="sent_to_recycle_bin",
                        )
                    except ImportError:
                        # 降级为移动到备份区
                        result = self.backup_manager.backup_file(fp, batch_id)
                results.append(result)
            except Exception as e:
                results.append(CleanResult(
                    path=fp, success=False, bytes_freed=0,
                    action="failed", error=str(e),
                ))

        return results

    def estimate_freed_space(self, file_paths: list[str]) -> int:
        """估算清理后释放的总空间"""
        total = 0
        for fp in file_paths:
            if self._should_keep(fp):
                continue
            path = Path(fp)
            if path.exists():
                total += path.stat().st_size
        return total

    def get_summary(self, results: list[CleanResult]) -> dict:
        """获取清理结果摘要"""
        success = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        return {
            "total_files": len(results),
            "success_count": len(success),
            "failed_count": len(failed),
            "total_freed": sum(r.bytes_freed for r in success),
        }
