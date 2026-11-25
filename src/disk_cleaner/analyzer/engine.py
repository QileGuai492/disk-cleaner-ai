"""分析引擎——串联缓存、规则、AI 的核心编排器"""

import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from disk_cleaner.scanner.walker import FileInfo, scan_directory
from disk_cleaner.analyzer.rules import Rule, RuleEngine
from disk_cleaner.analyzer.profiler import ContentProfiler
from disk_cleaner.analyzer.ai_client import (
    AIProvider,
    AIUnavailableError,
    FileAnalysisInput,
    build_single_file_prompt,
    build_cluster_prompt,
    parse_ai_response,
)
from disk_cleaner.analyzer.anonymizer import PathAnonymizer
from disk_cleaner.analyzer.result import AnalysisResult
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
        cloud_blocklist: list[str] | None = None,
        privacy_level: str | None = None,
        max_dirs: int | None = None,
        skip_symlinks: bool | None = None,
        ai_max_retries: int | None = None,
        ai_rate_limit_rpm: int | None = None,
    ):
        self.db = db
        self.cache = AnalysisCache(db)
        self.rules = RuleEngine()
        self.rules.add_builtin_rules()
        self._load_persisted_rules()
        self.profiler = ContentProfiler()
        self.fingerprints = FingerprintDB()
        self.ai_provider = ai_provider
        self.ai_model = ai_model
        self.api_key = api_key
        config = None
        if (
            cloud_blocklist is None or privacy_level is None or max_dirs is None
            or skip_symlinks is None or ai_max_retries is None or ai_rate_limit_rpm is None
        ):
            try:
                from disk_cleaner.config import load_config
                config = load_config()
                if cloud_blocklist is None:
                    cloud_blocklist = config.ai.cloud_blocklist
                if privacy_level is None:
                    privacy_level = config.privacy.level
                if max_dirs is None:
                    max_dirs = config.scan.max_dirs
                if skip_symlinks is None:
                    skip_symlinks = config.scan.skip_symlinks
                if ai_max_retries is None:
                    ai_max_retries = config.ai.max_retries
                if ai_rate_limit_rpm is None:
                    ai_rate_limit_rpm = config.ai.rate_limit_rpm
            except Exception:
                pass
        self.ai_max_retries = ai_max_retries if ai_max_retries is not None else 3
        self.ai_rate_limit_rpm = ai_rate_limit_rpm if ai_rate_limit_rpm is not None else 30
        blocked_extensions = config.privacy.extension_blocklist if config is not None else None
        self.anonymizer = PathAnonymizer(
            level=privacy_level or "strict",
            blocked_extensions=blocked_extensions,
        )
        self.cloud_blocklist = cloud_blocklist or []
        self.max_dirs = max_dirs if max_dirs is not None else 5000
        self.skip_symlinks = True if skip_symlinks is None else bool(skip_symlinks)
        self._ai: AIProvider | None = None
        self._local_ai = AIProvider.create("local", model="heuristic")
        self._stats = self._new_stats()
        self._cancelled = False

    @staticmethod
    def _new_stats() -> dict:
        return {
            "cache_hits": 0,
            "rule_hits": 0,
            "ai_calls": 0,
            "degraded": 0,
            "learned": 0,
            "total": 0,
        }

    def _load_persisted_rules(self) -> None:
        """从 SQLite 加载用户/AI 沉淀的规则。"""
        try:
            rows = self.db.get_rules()
        except Exception:
            return
        for row in rows:
            try:
                self.rules.add_rule(Rule(
                    pattern=row["pattern"],
                    decision=row["decision"],
                    confidence=float(row.get("confidence") or 0.9),
                    priority=int(row.get("priority") or 0),
                    source=row.get("source") or "builtin",
                ))
            except Exception:
                continue

    def _learn_from_results(self, results: list[dict]) -> list:
        """从高置信结果中沉淀规则，并写入数据库。"""
        learnable = [
            r for r in results
            if r.get("source") in ("ai", "rule")
            and r.get("decision") in ("safe_to_delete", "likely_safe")
            and float(r.get("confidence") or 0) >= 0.90
        ]
        try:
            new_rules = self.rules.learn_from_results(learnable, threshold=10)
        except Exception:
            return []
        for rule in new_rules:
            try:
                self.db.save_rule(
                    pattern=rule.pattern,
                    decision=rule.decision,
                    confidence=rule.confidence,
                    source=rule.source,
                    priority=rule.priority,
                )
            except Exception:
                pass
        if new_rules:
            self._stats["learned"] = self._stats.get("learned", 0) + len(new_rules)
        return new_rules

    def _begin_run(self) -> None:
        """每次分析开始重置取消标记与统计，避免跨请求污染。"""
        self._stats = self._new_stats()
        self._cancelled = False

    @property
    def ai(self) -> AIProvider:
        if self._ai is None:
            timeout_seconds = 30.0
            budget_usd = 0.0
            input_cost = 0.0
            output_cost = 0.0
            try:
                from disk_cleaner.config import load_config
                ai_config = load_config().ai
                timeout_seconds = ai_config.timeout_seconds
                budget_usd = ai_config.budget_usd
                input_cost = ai_config.input_cost_per_million
                output_cost = ai_config.output_cost_per_million
            except Exception:
                pass
            self._ai = AIProvider.create(
                self.ai_provider,
                api_key=self.api_key,
                model=self.ai_model,
                max_retries=self.ai_max_retries,
                rate_limit_rpm=self.ai_rate_limit_rpm,
                timeout_seconds=timeout_seconds,
                budget_usd=budget_usd,
                input_cost_per_million=input_cost,
                output_cost_per_million=output_cost,
            )
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
            self._begin_run()
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
        self._begin_run()
        file_infos = scan_directory(
            path, top_n=top_n, recursive=recursive,
            max_dirs=self.max_dirs, skip_symlinks=self.skip_symlinks,
        )
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
                results.append(AnalysisResult(
                    path=fi.path, name=fi.name, size=fi.size,
                    size_mb=fi.size_mb, extension=fi.extension,
                    mtime=fi.mtime, decision="needs_review",
                    confidence=0.0, reason="分析已取消", risk="none", source="cancelled",
                ))
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
        self._learn_from_results(results)
        return results

    def analyze_directory_stream(
        self, path: str, top_n: int = 50, force: bool = False, recursive: bool = True
    ):
        """流式分析——逐文件 yield 结果，供 SSE 推送"""
        self._begin_run()

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

        file_infos = scan_directory(
            path, top_n=top_n, recursive=recursive,
            max_dirs=self.max_dirs, skip_symlinks=self.skip_symlinks,
        )
        self._stats["total"] = len(file_infos)
        total = len(file_infos)

        if not file_infos:
            return

        # 第一遍：缓存命中直接 yield；其余（含 force）进入规则层
        needs_rules: list[FileInfo] = []
        learnable_results: list[dict] = []
        for fi in file_infos:
            if self._cancelled:
                yield {"type": "cancelled", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total}
                return
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
                result = self._cache_to_result(fi, cached)
                learnable_results.append(result)
                yield {"type": "result", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total, "result": result}
                continue
            needs_rules.append(fi)

        # 第二遍：规则匹配；force 只跳过缓存，不跳过规则
        needs_ai: list[FileInfo] = []
        for fi in needs_rules:
            if self._cancelled:
                yield {"type": "cancelled", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total}
                return
            match = self.rules.evaluate(fi)
            if match and match.confidence >= 0.85:
                self._stats["rule_hits"] += 1
                result = self._rule_to_result(fi, match)
                self._save_to_cache(fi, match.decision, match.confidence, match.reason, "rule")
                learnable_results.append(result)
                yield {"type": "result", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total, "result": result}
                continue
            needs_ai.append(fi)

        # 第三遍：AI/本地分析，逐文件 yield
        for fi in needs_ai:
            if self._cancelled:
                yield {"type": "cancelled", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total}
                return
            ai_result = self._analyze_single(fi)
            learnable_results.append(ai_result)
            yield {"type": "result", "current": self._stats["cache_hits"] + self._stats["rule_hits"] + self._stats["ai_calls"], "total": total, "result": ai_result}

        self._learn_from_results(learnable_results)

    def relocate_analysis(self, path: str) -> list[dict]:
        """搬迁分析——识别可搬到 D 盘的大文件"""
        file_infos = scan_directory(
            path, top_n=100, min_size=10 * 1024 * 1024,
            max_dirs=self.max_dirs, skip_symlinks=self.skip_symlinks,
        )
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
        """分析单个文件：云端 AI 失败时显式降级，绝不冒充 AI。"""
        self._stats["ai_calls"] += 1
        use_cloud = self.ai_provider != "local"

        if use_cloud and not self.anonymizer.should_send_to_cloud(fi.path, self.cloud_blocklist):
            return self._analyze_local(
                fi,
                "该文件类型或路径禁止上传云端，已用本地规则判断",
                source="local",
            )

        display_path = self.anonymizer.anonymize(fi.path) if use_cloud else fi.path
        inp = self._build_input(fi, display_path)

        # 只在云端 AI 时读取文件内容摘要
        if use_cloud:
            try:
                summary = self.profiler.profile(fi.path)
                if summary and summary.file_type != "unknown":
                    inp.content_summary = summary.to_ai_dict()
            except Exception:
                pass

        prompt = build_single_file_prompt(inp)

        if not use_cloud:
            response = self._local_ai.analyze(prompt)
            output = parse_ai_response(response)
            self._save_to_cache(
                fi, output.decision, output.confidence, output.reason, "local", output.risk
            )
            return self._result_from_output(fi, output, "local")

        try:
            response = self.ai.analyze(prompt)
        except AIUnavailableError as e:
            self._stats["degraded"] += 1
            try:
                from disk_cleaner.logging_utils import get_logger
                get_logger("engine").warning("AI 不可用，降级为本地规则: %s (%s)", fi.path, e)
            except Exception:
                pass
            return self._analyze_local(fi, f"AI 不可用：{e}", source="degraded")

        output = parse_ai_response(response)
        self._save_to_cache(
            fi, output.decision, output.confidence, output.reason, "ai", output.risk
        )
        return self._result_from_output(fi, output, "ai")

    def _build_input(self, fi: FileInfo, display_path: str) -> FileAnalysisInput:
        keywords = [
            p for p in Path(display_path).parts
            if not (len(p) == 3 and p[1] == ":" and p[2] == "\\")
        ]
        return FileAnalysisInput(
            path=display_path,
            size_mb=fi.size_mb,
            extension=fi.extension,
            last_modified=datetime.fromtimestamp(fi.mtime).strftime("%Y-%m-%d"),
            path_keywords=keywords,
            analysis_round=1,
        )

    def _analyze_local(self, fi: FileInfo, note: str, source: str) -> dict:
        """本地启发式分析；只用于 local/degraded，不写入 AI 缓存。"""
        inp = self._build_input(fi, fi.path)
        prompt = build_single_file_prompt(inp)
        response = self._local_ai.analyze(prompt)
        output = parse_ai_response(response)
        reason = f"{note}；{output.reason}" if note else output.reason
        if source == "local":
            self._save_to_cache(
                fi, output.decision, output.confidence, reason, "local", output.risk
            )
        return self._result_from_output(fi, output, source, reason=reason)

    def _result_from_output(self, fi: FileInfo, output, source: str, reason: str | None = None) -> AnalysisResult:
        return AnalysisResult(
            path=fi.path, name=fi.name, size=fi.size, size_mb=fi.size_mb,
            extension=fi.extension, mtime=fi.mtime,
            decision=output.decision, confidence=output.confidence,
            reason=output.reason if reason is None else reason,
            risk=output.risk, source=source,
        )

    def _save_to_cache(
        self,
        fi: FileInfo,
        decision: str,
        confidence: float,
        reason: str,
        source: str,
        risk: str = "none",
    ) -> None:
        try:
            self.cache.upsert(
                file_path=fi.path, mtime=int(fi.mtime), size_bytes=fi.size,
                decision=decision, confidence=confidence, reason=reason,
                risk=risk, ai_model=f"{self.ai_model}({source})",
            )
        except Exception:
            pass

    def _cache_to_result(self, fi: FileInfo, cached: dict) -> dict:
        ai_model = cached.get("ai_model", "")
        m = re.search(r"\(([^)]+)\)", ai_model)
        orig = m.group(1) if m else ""
        return AnalysisResult(
            path=fi.path, name=fi.name, size=fi.size, size_mb=fi.size_mb,
            extension=fi.extension, mtime=fi.mtime,
            decision=cached["decision"], confidence=cached["confidence"],
            reason=cached.get("reason", ""), risk=cached.get("risk", "none"),
            source=f"{orig}+cache" if orig else "cache", cached=True,
        )

    def _rule_to_result(self, fi: FileInfo, match) -> AnalysisResult:
        return AnalysisResult(
            path=fi.path, name=fi.name, size=fi.size, size_mb=fi.size_mb,
            extension=fi.extension, mtime=fi.mtime,
            decision=match.decision, confidence=match.confidence,
            reason=match.reason, risk="none", source="rule",
        )
