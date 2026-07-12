"""分析引擎——串联缓存、规则、AI 的核心编排器"""

import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from disk_cleaner.scanner.walker import FileInfo, scan_directory
from disk_cleaner.analyzer.rules import RuleEngine
from disk_cleaner.analyzer.profiler import ContentProfiler
from disk_cleaner.analyzer.ai_client import (
    AIProvider,
    FileAnalysisInput,
    build_single_file_prompt,
    build_cluster_prompt,
    parse_ai_response,
)
from disk_cleaner.analyzer.fingerprints import FingerprintDB
from disk_cleaner.analyzer.deps import DependencyAnalyzer
from disk_cleaner.db.models import Database, AnalysisCache


class AnalysisEngine:
    """分析引擎——统一入口，接管缓存/规则/AI 的调度"""

    def __init__(
        self,
        db: Database,
        ai_provider: str = "ollama",
        ai_model: str = "qwen2.5:1.5b",
        api_key: str = "",
    ):
        self.db = db
        self.cache = AnalysisCache(db)
        self.rules = RuleEngine()
        self.rules.add_builtin_rules()
        self.profiler = ContentProfiler()
        self.fingerprints = FingerprintDB()
        self.ai_provider = ai_provider
        self.ai_model = ai_model
        self.api_key = api_key
        self._ai: AIProvider | None = None
        self._stats = {"cache_hits": 0, "rule_hits": 0, "ai_calls": 0, "total": 0}
        self._cancelled = False

    @property
    def ai(self) -> AIProvider:
        if self._ai is None:
            self._ai = AIProvider.create(self.ai_provider, api_key=self.api_key, model=self.ai_model)
        return self._ai

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def cancel(self) -> None:
        self._cancelled = True

    def analyze_path(
        self, path: str, top_n: int = 50, force: bool = False, recursive: bool = True
    ) -> list[dict]:
        """分析路径（文件或目录），自动判断类型"""
        if os.path.isfile(path):
            fi = FileInfo(
                path=os.path.abspath(path),
                size=os.path.getsize(path),
                mtime=os.path.getmtime(path),
            )
            self._stats["total"] = 1
            mtime_int = int(fi.mtime)
            if not force:
                cached = self.cache.get(fi.path, mtime_int, fi.size)
                if cached:
                    self._stats["cache_hits"] = 1
                    return [self._cache_to_result(fi, cached)]
            match = self.rules.evaluate(fi)
            if match and match.confidence >= 0.85:
                self._stats["rule_hits"] = 1
                result = self._rule_to_result(fi, match)
                self._save_to_cache(fi, match.decision, match.confidence, match.reason, "rule")
                return [result]
            return [self._analyze_single(fi)]
        return self.analyze_directory(path, top_n=top_n, force=force, recursive=recursive)

    def analyze_directory(
        self, path: str, top_n: int = 50, force: bool = False, recursive: bool = True
    ) -> list[dict]:
        """分析目录中的所有文件，返回分析结果列表"""
        file_infos = scan_directory(path, top_n=top_n, recursive=recursive)
        self._stats["total"] = len(file_infos)

        if not file_infos:
            return []

        results: list[dict] = []
        needs_rules: list[FileInfo] = []

        for fi in file_infos:
            if force:
                needs_rules.append(fi)
                continue
            mtime_int = int(fi.mtime)
            cached = self.cache.get(fi.path, mtime_int, fi.size)
            if cached:
                reason = cached.get("reason", "")
                if "AI 响应格式异常" in reason or "响应被截断" in reason:
                    needs_rules.append(fi)
                    continue
                self._stats["cache_hits"] += 1
                results.append(self._cache_to_result(fi, cached))
                continue
            needs_rules.append(fi)

        needs_ai: list[FileInfo] = []
        for fi in needs_rules:
            match = self.rules.evaluate(fi)
            if match and match.confidence >= 0.85:
                self._stats["rule_hits"] += 1
                result = self._rule_to_result(fi, match)
                self._save_to_cache(fi, match.decision, match.confidence, match.reason, "rule")
                results.append(result)
            else:
                needs_ai.append(fi)

        for fi in needs_ai:
            if self._cancelled:
                results.append({
                    "path": fi.path, "name": fi.name, "size": fi.size,
                    "size_mb": fi.size_mb, "extension": fi.extension,
                    "mtime": fi.mtime, "decision": "needs_review",
                    "confidence": 0.0, "reason": "分析已取消", "risk": "none", "source": "cancelled",
                })
                continue
            ai_result = self._analyze_single(fi)
            results.append(ai_result)

        # 排序：当前目录文件在前，子目录按路径聚拢；同目录内按判定优先级→大小降序
        decision_order = {"safe_to_delete": 0, "likely_safe": 1, "needs_review": 2, "keep": 3, "critical": 4}
        scan_root = os.path.abspath(path)
        def _sort_key(r):
            rel = os.path.relpath(r["path"], scan_root)
            depth = rel.count(os.sep)
            parent = os.path.dirname(rel)
            return (depth, parent, decision_order.get(r["decision"], 2), -r["size"])
        results.sort(key=_sort_key)
        return results

    def analyze_directory_stream(
        self, path: str, top_n: int = 50, force: bool = False, recursive: bool = True
    ):
        """流式分析——逐文件 yield 结果，供 SSE 推送"""
        from collections.abc import Generator as Gen

        # 单文件处理
        if os.path.isfile(path):
            fi = FileInfo(
                path=os.path.abspath(path),
                size=os.path.getsize(path),
                mtime=os.path.getmtime(path),
            )
            self._stats["total"] = 1
            mtime_int = int(fi.mtime)
            if not force:
                cached = self.cache.get(fi.path, mtime_int, fi.size)
                if cached:
                    reason = cached.get("reason", "")
                    if "AI 响应格式异常" not in reason and "响应被截断" not in reason:
                        self._stats["cache_hits"] += 1
                        yield {"type": "result", "current": 1, "total": 1, "result": self._cache_to_result(fi, cached)}
                        return
            result = self._analyze_single(fi)
            yield {"type": "result", "current": 1, "total": 1, "result": result}
            return

        file_infos = scan_directory(path, top_n=top_n, recursive=recursive)
        self._stats["total"] = len(file_infos)
        total = len(file_infos)

        if not file_infos:
            return

        # 第一遍：缓存命中 + 规则匹配直接 yield
        needs_ai: list[FileInfo] = []
        for fi in file_infos:
            if self._cancelled:
                yield {"type": "cancelled", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total}
                return
            if force:
                needs_ai.append(fi)
                continue
            mtime_int = int(fi.mtime)
            cached = self.cache.get(fi.path, mtime_int, fi.size)
            if cached:
                reason = cached.get("reason", "")
                if "AI 响应格式异常" in reason or "响应被截断" in reason:
                    needs_ai.append(fi)
                    continue
                self._stats["cache_hits"] += 1
                yield {"type": "result", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total, "result": self._cache_to_result(fi, cached)}
                continue
            match = self.rules.evaluate(fi)
            if match and match.confidence >= 0.85:
                self._stats["rule_hits"] += 1
                result = self._rule_to_result(fi, match)
                self._save_to_cache(fi, match.decision, match.confidence, match.reason, "rule")
                yield {"type": "result", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total, "result": result}
                continue
            needs_ai.append(fi)

        # 第二遍：AI 分析，逐文件 yield
        for fi in needs_ai:
            if self._cancelled:
                yield {"type": "cancelled", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total}
                return
            ai_result = self._analyze_single(fi)
            yield {"type": "result", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total, "result": ai_result}

    def relocate_analysis(self, path: str) -> list[dict]:
        """搬迁分析——识别可搬到 D 盘的大文件"""
        file_infos = scan_directory(path, top_n=100, min_size=10 * 1024 * 1024)
        results: list[dict] = []
        for fi in file_infos:
            if any(sys_dir in fi.path.lower() for sys_dir in ["\\windows\\", "\\system32\\", "\\winsxs\\"]):
                continue
            registry_refs = self._check_registry_refs(fi.path)
            is_junction = os.path.islink(fi.path) if hasattr(os, "islink") else False
            if registry_refs >= 10:
                decision, reason = "immovable", f"注册表引用 {registry_refs} 处，不可搬迁"
            elif registry_refs >= 2:
                decision, reason = "movable_with_junction", f"有 {registry_refs} 处注册表引用，搬走后需创建 Junction"
            elif is_junction:
                decision, reason = "immovable", "已是符号链接/Junction"
            elif fi.path.lower().endswith((".exe", ".dll", ".sys")):
                decision, reason = "movable_risky", "可执行文件搬迁有风险"
            else:
                decision, reason = "movable_direct", "无注册表依赖，可直接搬迁"
            results.append({
                "path": fi.path, "name": fi.name, "size": fi.size, "size_mb": fi.size_mb,
                "decision": decision, "reason": reason, "registry_refs": registry_refs,
            })
        order = {"movable_direct": 0, "movable_with_junction": 1, "movable_risky": 2, "immovable": 3}
        results.sort(key=lambda r: (order.get(r["decision"], 2), -r["size"]))
        return results

    def _check_registry_refs(self, path: str) -> int:
        """检查文件在注册表中的引用次数"""
        import winreg
        name = os.path.basename(path)
        count = 0
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    for j in range(winreg.QueryInfoKey(subkey)[1]):
                        try:
                            val = winreg.EnumValue(subkey, j)
                            if isinstance(val[1], str) and name.lower() in val[1].lower():
                                count += 1
                        except Exception:
                            pass
                    winreg.CloseKey(subkey)
                except Exception:
                    pass
            winreg.CloseKey(key)
        except Exception:
            pass
        return count

    def _analyze_single(self, fi: FileInfo) -> dict:
        """AI 分析单个文件（本地内容预读 → AI 判断）"""
        self._stats["ai_calls"] += 1
        inp = FileAnalysisInput(
            path=fi.path, size_mb=fi.size_mb, extension=fi.extension,
            last_modified=datetime.fromtimestamp(fi.mtime).strftime("%Y-%m-%d"),
            path_keywords=fi.path_keywords, analysis_round=1,
        )
        # 只在云端 AI 时读文件内容（本地模式用扩展名+路径判断足够快）
        if self.ai_provider != "local":
            try:
                summary = self.profiler.profile(fi.path)
                if summary and summary.file_type != "unknown":
                    inp.content_summary = summary.to_ai_dict()
            except Exception:
                pass
        prompt = build_single_file_prompt(inp)
        response = self.ai.analyze(prompt)
        output = parse_ai_response(response)
        data_source = "local" if self.ai_provider == "local" else "ai"
        self._save_to_cache(fi, output.decision, output.confidence, output.reason, data_source)
        return {
            "path": fi.path, "name": fi.name, "size": fi.size, "size_mb": fi.size_mb,
            "extension": fi.extension, "mtime": fi.mtime,
            "decision": output.decision, "confidence": output.confidence,
            "reason": output.reason, "risk": output.risk,
            "source": data_source,
        }

    def _save_to_cache(self, fi: FileInfo, decision: str, confidence: float, reason: str, source: str) -> None:
        try:
            self.cache.upsert(
                file_path=fi.path, mtime=int(fi.mtime), size_bytes=fi.size,
                decision=decision, confidence=confidence, reason=reason,
                risk="none", ai_model=f"{self.ai_model}({source})",
            )
        except Exception:
            pass

    def _cache_to_result(self, fi: FileInfo, cached: dict) -> dict:
        ai_model = cached.get("ai_model", "")
        m = re.search(r"\(([^)]+)\)", ai_model)
        orig = m.group(1) if m else ""
        return {
            "path": fi.path, "name": fi.name, "size": fi.size, "size_mb": fi.size_mb,
            "extension": fi.extension, "mtime": fi.mtime,
            "decision": cached["decision"], "confidence": cached["confidence"],
            "reason": cached.get("reason", ""), "risk": cached.get("risk", "none"),
            "source": f"{orig}+cache" if orig else "cache",
        }

    def _rule_to_result(self, fi: FileInfo, match) -> dict:
        return {
            "path": fi.path, "name": fi.name, "size": fi.size, "size_mb": fi.size_mb,
            "extension": fi.extension, "mtime": fi.mtime,
            "decision": match.decision, "confidence": match.confidence,
            "reason": match.reason, "risk": "none", "source": "rule",
        }
