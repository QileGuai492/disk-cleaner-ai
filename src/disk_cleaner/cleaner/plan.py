"""清理计划——执行前的可审核清单。"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field


@dataclass
class CleanPlan:
    """一次清理的完整计划：只描述，不执行。"""

    paths: list[str]
    mode: str = "backup"
    backup_dir: str = ""
    total_bytes: int = 0
    warnings: list[str] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    plan_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)

    @property
    def allowed(self) -> bool:
        """没有任何路径被安全策略拒绝时才允许执行。"""
        return bool(self.paths) and not self.rejected

    @property
    def total_mb(self) -> float:
        return round(self.total_bytes / (1024 * 1024), 1)

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "paths": list(self.paths),
            "mode": self.mode,
            "backup_dir": self.backup_dir,
            "total_bytes": self.total_bytes,
            "total_mb": self.total_mb,
            "warnings": list(self.warnings),
            "rejected": list(self.rejected),
            "allowed": self.allowed,
            "created_at": self.created_at,
        }
