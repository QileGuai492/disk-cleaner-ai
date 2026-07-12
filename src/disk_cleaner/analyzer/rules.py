"""规则引擎——本地第一层过滤"""

import fnmatch
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from disk_cleaner.scanner.walker import FileInfo


@dataclass
class MatchResult:
    """规则匹配结果"""

    decision: str  # safe_to_delete / likely_safe / keep / ...
    confidence: float  # 0.0 ~ 1.0
    rule_pattern: str
    reason: str


@dataclass
class Rule:
    """单条判定规则"""

    pattern: str
    decision: str
    confidence: float
    priority: int = 0  # 越高越优先
    source: str = "builtin"  # builtin / ai_learned / user_defined / community
    is_regex: bool = False
    hit_count: int = 0
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        if self.is_regex:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)

    def matches(self, file_info: FileInfo) -> bool:
        """检查文件是否匹配此规则"""
        path = file_info.path
        name = file_info.name

        if self.is_regex:
            return bool(self._compiled.search(path))

        # glob 模式：先试完整路径，再试文件名
        if fnmatch.fnmatch(path, self.pattern):
            return True
        if fnmatch.fnmatch(name, self.pattern):
            return True

        # 路径包含模式：如 **\\AppData\\** 匹配任何包含 AppData 的路径
        if "**" in self.pattern:
            # 把 ** 替换为 * 以匹配任意层级
            simplified = self.pattern.replace("**", "*")
            # 统一路径分隔符
            simplified = simplified.replace("\\", "/")
            path_normalized = path.replace("\\", "/")
            if fnmatch.fnmatch(path_normalized, simplified):
                return True

            # 额外尝试：反向匹配——路径是否以 pattern 的尾部结束
            # 如 **\\System32\\** → 路径是否包含 */System32/*
            segments = self.pattern.split("**")
            last_segment = segments[-1].replace("\\", "/")
            if last_segment and fnmatch.fnmatch(path_normalized, f"*{last_segment}*"):
                return True

        return False

    def evaluate(self, file_info: FileInfo) -> Optional[MatchResult]:
        """对文件执行规则判定"""
        if not self.matches(file_info):
            return None
        self.hit_count += 1
        return MatchResult(
            decision=self.decision,
            confidence=self.confidence,
            rule_pattern=self.pattern,
            reason=f"匹配规则 {self.pattern} (来源: {self.source})",
        )


class RuleEngine:
    """规则引擎——在 AI 分析前用本地规则快速判定"""

    def __init__(self):
        self._rules: list[Rule] = []

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def add_rule(self, rule: Rule) -> None:
        """添加规则，同 pattern 时高优先级来源覆盖低优先级"""
        source_order = {"user_defined": 3, "community": 2, "ai_learned": 1, "builtin": 0}

        # 检查是否已有同 pattern 规则
        for i, existing in enumerate(self._rules):
            if existing.pattern == rule.pattern:
                existing_src = source_order.get(existing.source, 0)
                new_src = source_order.get(rule.source, 0)
                # 高优先级来源覆盖低优先级
                if new_src > existing_src or (
                    new_src == existing_src and rule.priority > existing.priority
                ):
                    self._rules[i] = rule
                return

        self._rules.append(rule)
        self._rules.sort(
            key=lambda r: (r.priority, source_order.get(r.source, 0)),
            reverse=True,
        )

    def evaluate(self, file_info: FileInfo) -> Optional[MatchResult]:
        """对文件进行规则匹配，返回第一条命中的规则结果"""
        for rule in self._rules:
            result = rule.evaluate(file_info)
            if result is not None:
                return result
        return None

    def add_builtin_rules(self) -> None:
        """加载内置规则（~30% 文件可被本地判定）"""
        builtin = [
            # 明显临时文件
            Rule("*.tmp", "safe_to_delete", 0.99, source="builtin"),
            Rule("*.temp", "safe_to_delete", 0.99, source="builtin"),
            Rule("~$*", "safe_to_delete", 0.99, source="builtin"),  # Office 临时文件
            Rule("*.dmp", "safe_to_delete", 0.95, source="builtin"),  # 崩溃转储
            Rule("*.mdmp", "safe_to_delete", 0.95, source="builtin"),
            # 系统临时目录
            Rule("**\\Temp\\**", "safe_to_delete", 0.95, source="builtin"),
            Rule("**\\Cache\\**", "likely_safe", 0.85, source="builtin"),
            # 日志文件（保留判断给 AI）
            Rule("*.log", "likely_safe", 0.80, source="builtin"),
            # 常见缓存
            Rule("**\\node_modules\\**", "safe_to_delete", 0.90, source="builtin"),
            Rule("**\\.npm\\_cacache\\**", "safe_to_delete", 0.95, source="builtin"),
            Rule("**\\__pycache__\\**", "safe_to_delete", 0.99, source="builtin"),
            # Windows 更新缓存
            Rule("**\\SoftwareDistribution\\Download\\**", "safe_to_delete", 0.90, source="builtin"),
        ]
        for rule in builtin:
            self.add_rule(rule)

    def learn_from_results(self, results: list[dict], threshold: int = 10) -> list[Rule]:
        """从 AI 分析结果中挖掘新规则

        挖掘策略：
        1. 扩展名模式：同扩展名、同决策的高频模式
        2. 路径模式：同目录模式的高频决策
        3. 组合模式：扩展名 + 目录的组合
        """
        new_rules: list[Rule] = []
        if len(results) < threshold:
            return new_rules

        # 策略 1：扩展名决策统计
        ext_groups: dict[str, dict[str, int]] = {}
        for r in results:
            path = r.get("path", "")
            decision = r.get("decision", "")
            ext = os.path.splitext(path)[1].lower()
            if not ext or len(ext) > 10:
                continue
            if ext not in ext_groups:
                ext_groups[ext] = {}
            ext_groups[ext][decision] = ext_groups[ext].get(decision, 0) + 1

        for ext, decisions in ext_groups.items():
            total = sum(decisions.values())
            if total < threshold:
                continue
            top_decision = max(decisions, key=decisions.get)
            top_count = decisions[top_decision]
            confidence = top_count / total
            if confidence >= 0.95 and top_decision in ("safe_to_delete", "likely_safe"):
                new_rules.append(Rule(
                    pattern=f"*.{ext}", decision=top_decision,
                    confidence=round(confidence, 2), source="ai_learned",
                ))

        # 策略 2：路径关键词决策统计
        path_decision: dict[str, dict[str, int]] = {}
        for r in results:
            path = r.get("path", "")
            decision = r.get("decision", "")
            # 提取父目录名作为路径关键词
            parent = os.path.basename(os.path.dirname(path)).lower()
            if not parent or parent in ("users", "windows", "program files"):
                continue
            key = f"**/{parent}/**"
            if key not in path_decision:
                path_decision[key] = {}
            path_decision[key][decision] = path_decision[key].get(decision, 0) + 1

        for pattern, decisions in path_decision.items():
            total = sum(decisions.values())
            if total < threshold:
                continue
            top_decision = max(decisions, key=decisions.get)
            top_count = decisions[top_decision]
            confidence = top_count / total
            if confidence >= 0.95 and top_decision in ("safe_to_delete", "likely_safe"):
                new_rules.append(Rule(
                    pattern=pattern, decision=top_decision,
                    confidence=round(confidence, 2), source="ai_learned",
                ))

        # 去重后添加
        added = 0
        for rule in new_rules:
            if not any(r.pattern == rule.pattern for r in self._rules):
                self.add_rule(rule)
                added += 1

        return new_rules
