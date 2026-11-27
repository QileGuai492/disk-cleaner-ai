"""证据层——把扫描结果整理成可解释的文件夹/关联组/证据。

聊天顾问只读取这里生成的结构化证据，不直接访问磁盘执行操作。
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Iterable

from disk_cleaner.analyzer.fingerprints import FingerprintDB
from disk_cleaner.cleaner.safety import SafetyPolicy


@dataclass
class Evidence:
    id: str
    type: str
    summary: str
    path: str | None = None
    confidence: float = 1.0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "summary": self.summary,
            "path": self.path,
            "confidence": self.confidence,
            "details": self.details,
        }


class EvidenceBook:
    """为一次聊天上下文分配稳定的 E1/E2... 编号。"""

    def __init__(self):
        self._items: list[Evidence] = []

    def add(
        self,
        type: str,
        summary: str,
        *,
        path: str | None = None,
        confidence: float = 1.0,
        details: dict[str, Any] | None = None,
    ) -> Evidence:
        item = Evidence(
            id=f"E{len(self._items) + 1}",
            type=type,
            summary=summary,
            path=path,
            confidence=max(0.0, min(1.0, confidence)),
            details=details or {},
        )
        self._items.append(item)
        return item

    @property
    def items(self) -> list[Evidence]:
        return list(self._items)

    def to_list(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self._items]


def _normalize(path: str) -> str:
    return path.replace("\\", "/")


def _parts(path: str) -> list[str]:
    return [p for p in PurePosixPath(_normalize(path)).parts if p and not p.endswith(":")]


def _under(path: str, folder: str) -> bool:
    try:
        return os.path.commonpath([
            os.path.normcase(os.path.abspath(path)),
            os.path.normcase(os.path.abspath(folder)),
        ]) == os.path.normcase(os.path.abspath(folder))
    except ValueError:
        return False


APP_ROOTS = (
    "program files", "program files (x86)", "programdata", "games",
    "documents", "downloads", "desktop", "pictures", "videos", "music",
)


def app_key(path: str) -> str:
    """从路径推断应用/文件夹名，用于跨目录关联。"""
    parts = _parts(path)
    lower = [p.lower() for p in parts]

    for root in ("program files", "program files (x86)", "programdata", "games"):
        if root in lower:
            index = lower.index(root) + 1
            if index < len(parts):
                return parts[index]

    if "appdata" in lower:
        index = lower.index("appdata") + 1
        if index < len(lower) and lower[index] in ("local", "roaming", "locallow"):
            index += 1
        if index < len(parts):
            return parts[index]

    for root in ("documents", "downloads", "desktop", "pictures", "videos", "music"):
        if root in lower:
            index = lower.index(root) + 1
            if index < len(parts):
                return parts[index]

    if len(parts) >= 2:
        return parts[-2]
    return ""


DATA_EXTENSIONS = {
    ".db", ".sqlite", ".sqlite3", ".mdb", ".pst", ".ost", ".kdbx",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mov", ".avi", ".mp3",
}
CACHE_SEGMENTS = {
    "cache", "caches", "cache2", "temp", "tmp", "logs", "log",
    "crashdumps", "dumps", "dump", "temporary",
}
CONFIG_EXTENSIONS = {".json", ".ini", ".yaml", ".yml", ".xml", ".conf", ".cfg", ".toml"}
CACHE_EXTENSIONS = {".log", ".tmp", ".temp", ".dmp", ".mdmp", ".hdmp"}


def classify_role(path: str) -> str:
    lower = _normalize(path).lower()
    parts = [p for p in lower.split("/") if p]
    ext = os.path.splitext(lower)[1]
    filename = parts[-1] if parts else ""
    if filename in {
        "build.gradle", "build.gradle.kts",
        "settings.gradle", "settings.gradle.kts",
        "gradle-wrapper.jar", "gradle-wrapper.properties",
    }:
        return "config"
    if any(part in CACHE_SEGMENTS for part in parts[:-1]) or ext in CACHE_EXTENSIONS:
        return "cache"
    if "appdata/roaming" in lower:
        return "config"
    if ext in CONFIG_EXTENSIONS:
        return "config"
    if any(root in lower for root in ("program files", "games")) or ext in (".exe", ".dll", ".sys"):
        return "program"
    if any(root in lower for root in ("documents", "desktop", "downloads", "pictures", "videos")):
        return "user_data"
    if ext in DATA_EXTENSIONS:
        return "user_data"
    return "data"


class RelatedGroupDetector:
    """按应用名和指纹把跨目录的文件聚合成关联组。"""

    def __init__(self, fingerprints: FingerprintDB | None = None):
        self.fingerprints = fingerprints or FingerprintDB()

    def build(self, results: Iterable[dict]) -> list[dict]:
        buckets: dict[str, list[dict]] = {}
        for result in results:
            path = result.get("path", "")
            key = app_key(path)
            if not key:
                continue
            buckets.setdefault(key.lower(), []).append(result)

        groups: list[dict] = []
        for key, files in buckets.items():
            parents = {os.path.dirname(_normalize(f.get("path", ""))) for f in files}
            if len(parents) < 2:
                continue
            label = app_key(files[0].get("path", "")) or key
            members = []
            for result in files:
                path = result.get("path", "")
                members.append({
                    "path": path,
                    "role": classify_role(path),
                    "size_bytes": int(result.get("size") or 0),
                    "decision": result.get("decision"),
                })
            roles = Counter(member["role"] for member in members)
            confidence = min(0.95, 0.55 + 0.1 * len(parents) + 0.05 * len(roles))
            groups.append({
                "group_id": f"G{len(groups) + 1}",
                "label": label,
                "confidence": round(confidence, 2),
                "members": sorted(members, key=lambda m: m["size_bytes"], reverse=True),
                "roles": dict(roles),
                "total_bytes": sum(m["size_bytes"] for m in members),
            })
        groups.sort(key=lambda g: g["total_bytes"], reverse=True)
        return groups


@dataclass
class FolderAssessment:
    path: str
    verdict: str
    confidence: float
    summary: str
    composition: dict[str, Any]
    activity: dict[str, Any]
    identity: dict[str, Any]
    keep_items: list[dict]
    clean_items: list[dict]
    risks: list[str]
    related_groups: list[dict]
    evidence: list[dict]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "summary": self.summary,
            "composition": self.composition,
            "activity": self.activity,
            "identity": self.identity,
            "keep_items": self.keep_items,
            "clean_items": self.clean_items,
            "risks": self.risks,
            "related_groups": self.related_groups,
            "evidence_ids": [e["id"] for e in self.evidence],
            "evidence": self.evidence,
        }


class FolderAssessor:
    """从一个目录下的扫描结果生成整体评估。"""

    def __init__(
        self,
        fingerprints: FingerprintDB | None = None,
        group_detector: RelatedGroupDetector | None = None,
        policy: SafetyPolicy | None = None,
    ):
        self.fingerprints = fingerprints or FingerprintDB()
        self.group_detector = group_detector or RelatedGroupDetector(self.fingerprints)
        self.policy = policy or SafetyPolicy()

    def assess(self, folder: str, results: Iterable[dict]) -> FolderAssessment:
        book = EvidenceBook()
        files = [r for r in results if _under(r.get("path", ""), folder)]
        if not files:
            book.add("composition", "目录下没有可分析的文件", path=folder)
            return FolderAssessment(
                path=folder, verdict="insufficient_evidence", confidence=0.2,
                summary="没有可用于判断的文件证据。",
                composition={}, activity={}, identity={},
                keep_items=[], clean_items=[], risks=["没有扫描结果"],
                related_groups=[], evidence=book.to_list(),
            )

        total_bytes = sum(int(f.get("size") or 0) for f in files)
        extensions = Counter(
            (os.path.splitext(f.get("path", ""))[1] or "(无扩展名)").lower()
            for f in files
        )
        top_files = sorted(files, key=lambda f: int(f.get("size") or 0), reverse=True)[:5]
        mtimes = [float(f.get("mtime") or 0) for f in files if f.get("mtime")]
        newest = max(mtimes) if mtimes else 0
        oldest = min(mtimes) if mtimes else 0
        days_since = int((datetime.now().timestamp() - newest) / 86400) if newest else -1
        roles = Counter(classify_role(f.get("path", "")) for f in files)

        composition = {
            "file_count": len(files),
            "total_bytes": total_bytes,
            "top_extensions": extensions.most_common(8),
            "largest_files": [
                {"path": f.get("path"), "size_bytes": int(f.get("size") or 0)}
                for f in top_files
            ],
            "roles": dict(roles),
        }
        activity = {
            "newest_mtime": datetime.fromtimestamp(newest).strftime("%Y-%m-%d") if newest else None,
            "oldest_mtime": datetime.fromtimestamp(oldest).strftime("%Y-%m-%d") if oldest else None,
            "days_since_newest": days_since,
        }

        fp_matches: list[str] = []
        for f in files[:200]:
            for fp in self.fingerprints.match(f.get("path", "")):
                if fp.app_name not in fp_matches:
                    fp_matches.append(fp.app_name)
        identity = {"app_guess": app_key(folder) or app_key(files[0].get("path", "")), "fingerprints": fp_matches}

        related = [
            group for group in self.group_detector.build(results)
            if any(_under(m["path"], folder) or _under(folder, m["path"]) for m in group["members"])
        ]

        book.add("composition", f"{len(files)} 个文件，共 {total_bytes / 1024**2:.1f} MB", path=folder)
        book.add("activity", f"最新修改 {activity['newest_mtime'] or '未知'}，距今天数 {days_since}", path=folder)
        if fp_matches:
            book.add("fingerprint", f"命中应用指纹：{', '.join(fp_matches)}", path=folder, confidence=0.8)
        if related:
            book.add("related", f"发现 {len(related)} 个关联组/同源目录", path=folder, confidence=0.7)

        safety = self.policy.validate(folder)
        if not safety.allowed:
            book.add("safety", f"安全策略拒绝：{safety.reason}", path=folder)
            return FolderAssessment(
                path=folder, verdict="keep", confidence=0.99,
                summary=f"该目录受保护，不建议清理：{safety.reason}",
                composition=composition, activity=activity, identity=identity,
                keep_items=[{"path": folder, "reason": safety.reason}],
                clean_items=[], risks=[safety.reason], related_groups=related,
                evidence=book.to_list(),
            )

        keep_items = []
        clean_items = []
        for f in files:
            item = {
                "path": f.get("path"),
                "size_bytes": int(f.get("size") or 0),
                "decision": f.get("decision"),
                "reason": f.get("reason", ""),
            }
            if f.get("decision") in ("keep", "critical"):
                keep_items.append(item)
            elif f.get("decision") in ("safe_to_delete", "likely_safe"):
                clean_items.append(item)

        user_data = roles.get("user_data", 0) > 0 or roles.get("config", 0) > 0
        risks: list[str] = []
        if user_data:
            risks.append("目录包含用户数据或配置，删除后可能无法恢复")
        if days_since >= 0 and days_since < 90:
            risks.append(f"最近 {days_since} 天仍有写入，可能仍在使用")
        if any(role == "program" for role in roles):
            risks.append("目录包含可执行文件或程序文件")

        if user_data and keep_items:
            verdict = "needs_review"
            summary = "目录混合了程序/缓存与用户数据，建议只清理明确的安全项，保留配置和数据。"
            confidence = 0.65
        elif clean_items and not keep_items:
            verdict = "clean_all_with_backup" if roles.get("cache", 0) else "clean_cache_only"
            summary = "目录内容以缓存/临时/日志为主，建议备份后清理。"
            confidence = 0.8
        elif clean_items and keep_items:
            verdict = "clean_cache_only"
            summary = "目录中一部分可清理，另一部分需要保留；建议只清理安全子集。"
            confidence = 0.72
        elif roles.get("program") or user_data:
            verdict = "keep"
            summary = "目录以程序或用户数据为主，不建议整体清理。"
            confidence = 0.7
        else:
            verdict = "needs_review"
            summary = "证据不足，建议人工确认或继续追问。"
            confidence = 0.4

        if related and verdict in ("clean_all_with_backup", "clean_cache_only"):
            risks.append("该目录与其它位置存在关联，整体删除前应检查同源目录")

        return FolderAssessment(
            path=folder, verdict=verdict, confidence=confidence, summary=summary,
            composition=composition, activity=activity, identity=identity,
            keep_items=keep_items[:50], clean_items=clean_items[:50],
            risks=risks, related_groups=related, evidence=book.to_list(),
        )
