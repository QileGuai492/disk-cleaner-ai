"""结构化分析结果。

继承 dict 以兼容现有 CLI/GUI/缓存代码，同时提供属性访问和
稳定的 to_dict/from_dict，供后续报告与聊天顾问复用。
"""

from __future__ import annotations

from typing import Any

_FIELDS = (
    "path", "name", "size", "size_mb", "extension", "mtime",
    "decision", "confidence", "reason", "risk", "source", "cached",
)


class AnalysisResult(dict):
    """单个文件的分析结果。"""

    def __init__(
        self,
        *,
        path: str,
        name: str,
        size: int,
        size_mb: float,
        extension: str,
        mtime: float,
        decision: str,
        confidence: float,
        reason: str,
        risk: str = "none",
        source: str = "unknown",
        cached: bool = False,
    ):
        super().__init__(
            path=path,
            name=name,
            size=size,
            size_mb=size_mb,
            extension=extension,
            mtime=mtime,
            decision=decision,
            confidence=confidence,
            reason=reason,
            risk=risk,
            source=source,
            cached=cached,
        )

    @property
    def path(self) -> str:
        return self["path"]

    @property
    def decision(self) -> str:
        return self["decision"]

    @property
    def confidence(self) -> float:
        return self["confidence"]

    @property
    def source(self) -> str:
        return self["source"]

    @property
    def cached(self) -> bool:
        return bool(self["cached"])

    def to_dict(self) -> dict[str, Any]:
        return dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisResult":
        values = {field: data.get(field) for field in _FIELDS}
        values["size"] = int(values.get("size") or 0)
        values["size_mb"] = float(values.get("size_mb") or 0.0)
        values["mtime"] = float(values.get("mtime") or 0.0)
        values["confidence"] = float(values.get("confidence") or 0.0)
        values["cached"] = bool(values.get("cached", False))
        values["path"] = values.get("path") or ""
        values["name"] = values.get("name") or ""
        values["extension"] = values.get("extension") or ""
        values["decision"] = values.get("decision") or "needs_review"
        values["reason"] = values.get("reason") or ""
        values["risk"] = values.get("risk") or "none"
        values["source"] = values.get("source") or "unknown"
        return cls(**values)
