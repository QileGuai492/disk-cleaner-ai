"""清理执行器——安全删除与备份管理"""

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from disk_cleaner.cleaner.plan import CleanPlan
from disk_cleaner.cleaner.safety import SafetyPolicy
from disk_cleaner.config import ConfigError, load_config


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

    def __init__(self, backup_root: str = "~/disk-cleaner-backup", retention_days: int = 30):
        self.backup_root = Path(os.path.expanduser(backup_root))
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.retention_days = max(1, int(retention_days))

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

    def list_files(self) -> list[dict]:
        """列出所有仍可恢复的备份文件（按备份时间倒序）。"""
        items: list[dict] = []
        for batch in self.list_batches():
            batch_id = batch.get("batch_id", "")
            for file_info in batch.get("files", []):
                backup_path = Path(str(file_info.get("backup_path", "")))
                original_path = str(file_info.get("original_path", ""))
                if not original_path or not backup_path.exists():
                    continue
                items.append({
                    "batch_id": batch_id,
                    "backup_path": str(backup_path),
                    "original_path": original_path,
                    "name": Path(original_path).name,
                    "size": int(file_info.get("size") or 0),
                    "backed_up_at": file_info.get("backed_up_at", ""),
                })
        items.sort(key=lambda item: item.get("backed_up_at", ""), reverse=True)
        return items

    def restore_files(self, items: list[dict]) -> list[CleanResult]:
        """恢复用户点选的备份文件；不覆盖原位置已有文件。"""
        selections = {
            (str(item.get("batch_id", "")), str(item.get("backup_path", "")))
            for item in items
        }
        if not selections:
            return []

        by_batch: dict[str, set[str]] = {}
        for batch_id, backup_path in selections:
            by_batch.setdefault(batch_id, set()).add(backup_path)

        results: list[CleanResult] = []
        for batch_id, selected_paths in by_batch.items():
            batch_dir = self.backup_root / batch_id
            manifest = batch_dir / "manifest.json"
            if not manifest.exists():
                continue
            data = json.loads(manifest.read_text(encoding="utf-8"))
            remaining = []
            changed = False
            for file_info in data.get("files", []):
                backup_path = str(file_info.get("backup_path", ""))
                if backup_path not in selected_paths:
                    remaining.append(file_info)
                    continue

                src = Path(backup_path)
                dest = Path(file_info["original_path"])
                try:
                    if not src.exists():
                        raise FileNotFoundError(f"备份文件不存在：{src}")
                    if dest.exists():
                        raise FileExistsError(f"目标已存在，未覆盖：{dest}")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(dest))
                    changed = True
                    results.append(CleanResult(
                        path=file_info["original_path"], success=True,
                        bytes_freed=int(file_info.get("size") or 0), action="restored",
                    ))
                except Exception as e:
                    remaining.append(file_info)
                    results.append(CleanResult(
                        path=file_info["original_path"], success=False,
                        bytes_freed=0, action="failed", error=str(e),
                    ))

            if changed:
                data["files"] = remaining
                manifest.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return results

    def delete_files(self, items: list[dict]) -> list[CleanResult]:
        """永久删除点选的备份文件；删除后无法恢复。"""
        selections = {
            (str(item.get("batch_id", "")), str(item.get("backup_path", "")))
            for item in items
        }
        if not selections:
            return []

        by_batch: dict[str, set[str]] = {}
        for batch_id, backup_path in selections:
            by_batch.setdefault(batch_id, set()).add(backup_path)

        results: list[CleanResult] = []
        for batch_id, selected_paths in by_batch.items():
            batch_dir = self.backup_root / batch_id
            manifest = batch_dir / "manifest.json"
            if not manifest.exists():
                continue
            data = json.loads(manifest.read_text(encoding="utf-8"))
            remaining = []
            changed = False
            for file_info in data.get("files", []):
                backup_path = str(file_info.get("backup_path", ""))
                if backup_path not in selected_paths:
                    remaining.append(file_info)
                    continue

                src = Path(backup_path)
                try:
                    freed = src.stat().st_size if src.exists() else 0
                    if src.exists():
                        src.unlink()
                    changed = True
                    results.append(CleanResult(
                        path=file_info["original_path"], success=True,
                        bytes_freed=freed, action="permanently_deleted",
                    ))
                except Exception as e:
                    remaining.append(file_info)
                    results.append(CleanResult(
                        path=file_info["original_path"], success=False,
                        bytes_freed=0, action="failed", error=str(e),
                    ))

            if changed:
                data["files"] = remaining
                manifest.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
                if not remaining:
                    self.delete_batch(batch_id)
        return results

    def restore_batch(self, batch_id: str) -> list[CleanResult]:
        """恢复一个批次中的所有文件（保留给 CLI/兼容接口）。"""
        manifest = self.backup_root / batch_id / "manifest.json"
        if not manifest.exists():
            return []
        data = json.loads(manifest.read_text(encoding="utf-8"))
        selections = [
            {"batch_id": batch_id, "backup_path": str(f.get("backup_path", ""))}
            for f in data.get("files", [])
        ]
        return self.restore_files(selections)

    def delete_batch(self, batch_id: str) -> bool:
        """永久删除备份批次"""
        batch_dir = self.backup_root / batch_id
        if batch_dir.exists():
            shutil.rmtree(str(batch_dir))
            return True
        return False

    def file_count(self, batch_id: str) -> int:
        """返回批次中仍待恢复的文件数量。"""
        manifest = self.backup_root / batch_id / "manifest.json"
        if not manifest.exists():
            return 0
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            return len(data.get("files", []))
        except Exception:
            return 0

    def prune_expired(self) -> int:
        """清理过期的备份批次，返回清理的批次数量。

        优先使用 manifest 中的 expires_at，其次 created_at + retention_days，
        最后才退回目录 mtime，避免用户复制/移动目录后过期时间失真。
        """
        now = time.time()
        count = 0
        for d in self.backup_root.iterdir():
            if not d.is_dir():
                continue
            try:
                expires_at = None
                manifest = d / "manifest.json"
                if manifest.exists():
                    data = json.loads(manifest.read_text(encoding="utf-8"))
                    raw = data.get("expires_at")
                    if raw:
                        try:
                            expires_at = datetime.fromisoformat(raw).timestamp()
                        except ValueError:
                            expires_at = None
                    if expires_at is None and data.get("created_at"):
                        try:
                            created = datetime.fromisoformat(data["created_at"]).timestamp()
                            expires_at = created + self.retention_days * 86400
                        except ValueError:
                            expires_at = None
                if expires_at is None:
                    expires_at = d.stat().st_mtime + self.retention_days * 86400
                if expires_at < now:
                    shutil.rmtree(str(d))
                    count += 1
            except Exception:
                pass
        return count


class CleanExecutor:
    """清理执行器——统一入口"""

    def __init__(
        self,
        backup_dir: str | None = None,
        policy: SafetyPolicy | None = None,
        retention_days: int | None = None,
    ):
        if backup_dir is None or retention_days is None:
            try:
                config = load_config()
                if backup_dir is None:
                    backup_dir = config.backup.dir
                if retention_days is None:
                    retention_days = config.backup.retention_days
            except ConfigError:
                pass
        self.backup_dir = os.path.expanduser(backup_dir or "~/disk-cleaner-backup")
        self.backup_manager = BackupManager(
            self.backup_dir,
            retention_days=retention_days if retention_days is not None else 30,
        )
        self.policy = policy or SafetyPolicy()
        self._keep_patterns: list[str] = []
        self.last_batch_id = ""
        self.last_plan: CleanPlan | None = None

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

    @staticmethod
    def _same_volume(path: str, other: str) -> bool:
        """判断两个路径是否位于同一个盘符/卷。"""
        try:
            return os.path.splitdrive(os.path.abspath(path))[0].lower() == os.path.splitdrive(
                os.path.abspath(other)
            )[0].lower()
        except Exception:
            return False

    def plan(
        self,
        file_paths: list[str],
        mode: str = "backup",
        scan_root: str | None = None,
    ) -> CleanPlan:
        """生成清理计划：先做安全策略校验，不执行任何删除。"""
        valid: list[str] = []
        rejected: list[dict] = []
        seen: set[str] = set()

        for fp in file_paths:
            absolute = os.path.abspath(str(fp))
            if absolute in seen:
                continue
            seen.add(absolute)

            decision = self.policy.validate(absolute, scan_root=scan_root)
            if not decision.allowed:
                rejected.append({"path": absolute, "reason": decision.reason})
                continue
            if self._should_keep(absolute):
                rejected.append({"path": absolute, "reason": "白名单保护"})
                continue
            valid.append(absolute)

        total_bytes = 0
        for fp in valid:
            try:
                if os.path.isfile(fp):
                    total_bytes += os.path.getsize(fp)
            except OSError:
                pass

        warnings: list[str] = []
        if valid and mode in ("backup", "recycle") and self._same_volume(valid[0], self.backup_dir):
            warnings.append(
                "备份目录与待清理文件在同一个分区，移动到备份区不会立即释放磁盘空间；"
                "需要删除备份后才会真正释放。"
            )

        plan = CleanPlan(
            paths=valid,
            mode=mode,
            backup_dir=self.backup_dir,
            total_bytes=total_bytes,
            warnings=warnings,
            rejected=rejected,
        )
        self.last_plan = plan
        return plan

    def execute(self, plan: CleanPlan) -> list[CleanResult]:
        """执行一个已经通过安全策略的清理计划。"""
        self.last_plan = plan
        self.last_batch_id = ""

        results: list[CleanResult] = [
            CleanResult(
                path=r["path"], success=False, bytes_freed=0,
                action="skipped", error=r["reason"],
            )
            for r in plan.rejected
        ]
        if not plan.paths:
            return results

        # 每次真实清理前顺带清理过期备份
        self.backup_manager.prune_expired()

        batch_id = ""

        def ensure_batch() -> str:
            nonlocal batch_id
            if not batch_id:
                batch_id = self.backup_manager.create_batch("cleanup")
            return batch_id

        for fp in plan.paths:
            path = Path(fp)
            if not path.exists():
                results.append(CleanResult(
                    path=fp, success=False, bytes_freed=0,
                    action="failed", error="文件不存在",
                ))
                continue

            try:
                file_size = path.stat().st_size
            except OSError as e:
                results.append(CleanResult(
                    path=fp, success=False, bytes_freed=0,
                    action="failed", error=str(e),
                ))
                continue

            try:
                if plan.mode == "backup":
                    result = self.backup_manager.backup_file(fp, ensure_batch())
                elif plan.mode == "permanent":
                    os.unlink(fp)
                    result = CleanResult(
                        path=fp, success=True, bytes_freed=file_size,
                        action="permanently_deleted",
                    )
                elif plan.mode == "recycle":
                    try:
                        import send2trash
                        send2trash.send2trash(fp)
                        result = CleanResult(
                            path=fp, success=True, bytes_freed=file_size,
                            action="sent_to_recycle_bin",
                        )
                    except ImportError:
                        # 没有 send2trash 时降级到备份区，但仍按实际动作记录
                        result = self.backup_manager.backup_file(fp, ensure_batch())
                else:
                    result = CleanResult(
                        path=fp, success=False, bytes_freed=0,
                        action="failed", error=f"未知清理模式: {plan.mode}",
                    )
                results.append(result)
            except Exception as e:
                results.append(CleanResult(
                    path=fp, success=False, bytes_freed=0,
                    action="failed", error=str(e),
                ))

        # 全部失败时不留下空批次
        if batch_id and self.backup_manager.file_count(batch_id) == 0:
            self.backup_manager.delete_batch(batch_id)
            batch_id = ""

        self.last_batch_id = batch_id
        try:
            from disk_cleaner.logging_utils import audit
            success = [r for r in results if r.success]
            audit(
                "clean",
                plan_id=plan.plan_id,
                mode=plan.mode,
                success=len(success),
                failed=len(results) - len(success),
                moved_bytes=sum(r.bytes_freed for r in success if r.action == "moved_to_backup"),
                freed_bytes=sum(r.bytes_freed for r in success if r.action == "permanently_deleted"),
                batch_id=batch_id,
                paths=plan.paths[:50],
                rejected=plan.rejected[:20],
            )
        except Exception:
            pass
        return results

    def clean(
        self, file_paths: list[str], mode: str = "backup"
    ) -> list[CleanResult]:
        """执行清理操作（兼容旧接口，内部先生成计划再执行）。"""
        plan = self.plan(file_paths, mode=mode)
        return self.execute(plan)

    def estimate_freed_space(self, file_paths: list[str]) -> int:
        """估算清理后释放的总空间（受安全策略保护）。"""
        total = 0
        for fp in file_paths:
            absolute = os.path.abspath(str(fp))
            if not self.policy.validate(absolute).allowed:
                continue
            if self._should_keep(absolute):
                continue
            try:
                if os.path.isfile(absolute):
                    total += os.path.getsize(absolute)
            except OSError:
                pass
        return total

    def get_summary(self, results: list[CleanResult]) -> dict:
        """获取清理结果摘要。

        total_freed 保留旧语义（成功项的文件大小总和）；
        total_moved 表示移入备份区的字节数；
        total_freed_real 表示立即释放的字节数（仅永久删除）。
        """
        success = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        return {
            "total_files": len(results),
            "success_count": len(success),
            "failed_count": len(failed),
            "total_freed": sum(r.bytes_freed for r in success),
            "total_moved": sum(
                r.bytes_freed for r in success if r.action == "moved_to_backup"
            ),
            "total_freed_real": sum(
                r.bytes_freed for r in success if r.action == "permanently_deleted"
            ),
        }
