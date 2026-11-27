"""AI 客户端——统一接口层，含重试、速率限制、降级"""

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FileAnalysisInput:
    """发给 AI 的文件分析输入"""

    path: str
    size_mb: float
    extension: str
    last_modified: str
    path_keywords: list[str] = field(default_factory=list)
    related_process: Optional[str] = None
    magic_bytes_guess: Optional[str] = None
    analysis_round: int = 1
    content_summary: Optional[dict] = None


@dataclass
class FileAnalysisOutput:
    """AI 分析结果"""

    decision: str  # safe_to_delete / likely_safe / needs_review / keep / critical
    confidence: float  # 0.0 ~ 1.0
    reason: str
    risk: str = "none"  # none / low / medium / high
    total_reclaimable_mb: float = 0.0
    warnings: list[str] = field(default_factory=list)

    @property
    def is_actionable(self) -> bool:
        """是否可自动处理（不需要用户介入）"""
        return self.decision in ("safe_to_delete", "likely_safe") and self.confidence >= 0.80


VALID_DECISIONS = frozenset({
    "safe_to_delete", "likely_safe", "needs_review", "keep", "critical",
})


def _safe_decision(value) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in VALID_DECISIONS:
            return normalized
    return "needs_review"


def _safe_confidence(value, default: float = 0.3) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, confidence))


def _safe_text(value, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _safe_risk(value) -> str:
    risk = _safe_text(value, "unknown").strip().lower()
    return risk if risk in ("none", "low", "medium", "high", "unknown") else "unknown"


def _salvage_fields(text: str, is_cluster: bool = False) -> FileAnalysisOutput | None:
    """JSON 被截断时按字段提取，尽量保留 decision/confidence/reason。"""
    if not text:
        return None
    decision_key = "cluster_decision" if is_cluster else "decision"
    reason_key = "cluster_reason" if is_cluster else "reason"
    decision_match = re.search(rf'"{decision_key}"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
    if not decision_match:
        decision_match = re.search(r'"decision"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
    confidence_match = re.search(r'"confidence"\s*:\s*([0-9]+(?:\.[0-9]+)?)', text, re.IGNORECASE)
    reason_match = re.search(rf'"{reason_key}"\s*:\s*"([^"]*)', text, re.IGNORECASE)
    risk_match = re.search(r'"risk"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
    if not decision_match and not reason_match:
        return None
    partial_reason = reason_match.group(1) if reason_match else ""
    if partial_reason:
        partial_reason += "…（响应被截断，仅恢复部分理由）"
    return FileAnalysisOutput(
        decision=_safe_decision(decision_match.group(1) if decision_match else None),
        confidence=_safe_confidence(confidence_match.group(1) if confidence_match else None, 0.3),
        reason=partial_reason or "AI 响应被截断，未能恢复理由",
        risk=_safe_risk(risk_match.group(1) if risk_match else None),
    )


def parse_ai_response(text: str, is_cluster: bool = False) -> FileAnalysisOutput:
    """从 AI 响应文本中解析分析结果（对模型输出做白名单与类型校验）"""
    if not text or not text.strip():
        return FileAnalysisOutput(
            decision="needs_review", confidence=0.0, reason="AI 返回空响应", risk="unknown"
        )

    # 尝试提取 JSON（可能在 ```json 代码块中）
    json_text = text
    json_match = re.search(r"```(?:json)?\s*\n?([\s\S]*?)\n?```", text)
    if json_match:
        json_text = json_match.group(1).strip()
    elif text.strip().startswith("{"):
        json_text = text.strip()

    truncated = False
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        data = None
        # 尝试补全截断的 JSON（max_tokens 不够时会被截断）
        if json_text.startswith("{") and not json_text.rstrip().endswith("}"):
            fixed = re.sub(r',\s*"[^"]*"\s*:\s*"[^"]*$', "", json_text.rstrip().rstrip(","))
            fixed += "}"
            try:
                data = json.loads(fixed)
                truncated = True
            except json.JSONDecodeError:
                data = None
        if data is None:
            salvaged = _salvage_fields(text, is_cluster)
            if salvaged is not None:
                return salvaged
            return FileAnalysisOutput(
                decision="needs_review",
                confidence=0.30,
                reason=f"AI 响应格式异常: {text[:200]}",
                risk="unknown",
            )

    if not isinstance(data, dict):
        return FileAnalysisOutput(
            decision="needs_review",
            confidence=0.30,
            reason=f"AI 响应不是 JSON 对象: {text[:200]}",
            risk="unknown",
        )

    suffix = "（响应被截断）" if truncated else ""

    if is_cluster:
        raw_warnings = data.get("warnings", [])
        warnings = [str(w) for w in raw_warnings] if isinstance(raw_warnings, list) else []
        try:
            reclaimable = float(data.get("total_reclaimable_mb", 0.0))
        except (TypeError, ValueError):
            reclaimable = 0.0
        return FileAnalysisOutput(
            decision=_safe_decision(data.get("cluster_decision", data.get("decision"))),
            confidence=_safe_confidence(data.get("confidence"), 0.80),
            reason=_safe_text(data.get("cluster_reason", data.get("reason"))) + suffix,
            total_reclaimable_mb=max(0.0, reclaimable),
            warnings=warnings,
        )

    return FileAnalysisOutput(
        decision=_safe_decision(data.get("decision")),
        confidence=_safe_confidence(data.get("confidence"), 0.5),
        reason=_safe_text(data.get("reason")) + suffix,
        risk=_safe_risk(data.get("risk")),
    )


def build_single_file_prompt(inp: FileAnalysisInput) -> str:
    """构建单文件分析 prompt（自然语言）"""
    from datetime import datetime as _dt
    lines = [
        "请分析以下文件是否可以安全删除：",
        f"  当前日期: {_dt.now().strftime('%Y-%m-%d')}（UTC）",
        f"  路径: {inp.path}",
        f"  大小: {inp.size_mb} MB",
        f"  扩展名: {inp.extension or '(无)'}",
        f"  最后修改: {inp.last_modified}",
        f"  路径关键词: {', '.join(inp.path_keywords) if inp.path_keywords else '(无)'}",
    ]
    if inp.related_process:
        lines.append(f"  关联进程: {inp.related_process}")
    if inp.magic_bytes_guess:
        lines.append(f"  文件头识别: {inp.magic_bytes_guess}")
    if inp.content_summary:
        cs = inp.content_summary
        summary_lines = []
        if cs.get("file_type"):
            summary_lines.append(f"文件类型: {cs['file_type']}")
        if cs.get("tables"):
            summary_lines.append(f"数据库表: {', '.join(cs['tables'])}")
        if cs.get("row_count"):
            summary_lines.append(f"行数: {cs['row_count']}")
        if cs.get("keys"):
            summary_lines.append(f"字段: {', '.join(cs['keys'][:15])}")
        if cs.get("field_count"):
            summary_lines.append(f"字段数: {cs['field_count']}")
        if cs.get("has_sensitive_keywords"):
            summary_lines.append("含敏感字段(如password)")
        if cs.get("newest_row"):
            summary_lines.append(f"最新记录: {cs['newest_row']}")
        if cs.get("extracted_head"):
            summary_lines.append(f"文件头部: {cs['extracted_head'][:200]}")
        if summary_lines:
            lines.append(f"  内容摘要: {'; '.join(summary_lines)}")

    lines.append("")
    lines.append("请以 JSON 格式返回分析结果：")
    lines.append('{"decision": "safe_to_delete|likely_safe|needs_review|keep|critical",')
    lines.append(' "confidence": 0.0~1.0, "reason": "判断理由", "risk": "none|low|medium|high"}')
    lines.append("只输出一行 JSON，不要 Markdown，不要解释；reason 不超过 80 个中文字符。")
    return "\n".join(lines)


def build_cluster_prompt(
    cluster_type: str,
    cluster_label: str,
    total_size_mb: float,
    files: list[FileAnalysisInput],
    related_clusters: Optional[list[str]] = None,
) -> str:
    """构建聚类组合分析 prompt"""
    lines = [
        f"请分析以下{cluster_type}聚类中的文件是否可以清理：",
        f"  聚类标签: {cluster_label}",
        f"  总大小: {total_size_mb} MB",
        f"  文件数: {len(files)}",
        "",
        "文件清单:",
    ]
    for i, f in enumerate(files, 1):
        lines.append(f"  {i}. {f.path} ({f.size_mb} MB, 修改于 {f.last_modified}, 类型: {f.extension})")

    if related_clusters:
        lines.append("")
        lines.append("关联聚类（同一应用的其他文件位置）:")
        for rc in related_clusters:
            lines.append(f"  - {rc}")

    lines.append("")
    lines.append("请以 JSON 格式返回分析结果：")
    lines.append('{"cluster_decision": "safe_to_delete|likely_safe|needs_review|keep|critical",')
    lines.append(' "cluster_reason": "整体判断理由",')
    lines.append(' "total_reclaimable_mb": 总可释放空间,')
    lines.append(' "files": [{"name": "...", "decision": "..."}],')
    lines.append(' "warnings": ["可选警告列表"]}')
    return "\n".join(lines)


class AIUnavailableError(RuntimeError):
    """AI 后端不可用，且不能伪造结果时抛出。"""


class AIProvider:
    """AI 后端统一接口——含重试、速率限制、显式失败"""

    SYSTEM_PROMPT = (
        "你是一个磁盘清理专家。根据文件路径、大小、类型、修改时间等信息，"
        "判断文件是否可以安全删除。只返回 JSON，不要有其他内容。"
    )

    def __init__(
        self,
        provider_name: str,
        api_key: str = "",
        model: str = "",
        max_retries: int = 3,
        rate_limit_rpm: int = 30,
        timeout_seconds: float = 30.0,
        max_output_tokens: int = 1200,
        budget_usd: float = 0.0,
        input_cost_per_million: float = 0.0,
        output_cost_per_million: float = 0.0,
        **kwargs,
    ):
        self.provider_name = provider_name
        self.api_key = api_key
        self.model = model
        self.kwargs = kwargs
        self.max_retries = max(1, int(max_retries))
        self.rate_limit_rpm = max(1, int(rate_limit_rpm))
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.max_output_tokens = max(256, int(max_output_tokens))
        self.budget_usd = max(0.0, float(budget_usd))
        self.input_cost_per_million = max(0.0, float(input_cost_per_million))
        self.output_cost_per_million = max(0.0, float(output_cost_per_million))
        self._call_times: list[float] = []
        self._total_calls = 0
        self._total_tokens = 0
        self._budget_used = 0.0
        self._consecutive_failures = 0
        self._state_lock = threading.RLock()
        self._rate_lock = threading.Lock()

    @classmethod
    def create(cls, provider: str, api_key: str = "", model: str = "", **kwargs) -> "AIProvider":
        """工厂方法"""
        supported = ("openai", "claude", "ollama", "gemini", "deepseek", "local")
        if provider not in supported:
            raise ValueError(f"不支持的 AI 后端: {provider}，支持: {', '.join(supported)}")
        provider_class = {
            "openai": OpenAIProvider,
            "claude": ClaudeProvider,
            "ollama": OllamaProvider,
            "gemini": GeminiProvider,
            "deepseek": DeepSeekProvider,
            "local": LocalProvider,
        }[provider]
        return provider_class(api_key=api_key, model=model, **kwargs)

    @property
    def stats(self) -> dict:
        with self._state_lock:
            return {
                "total_calls": self._total_calls,
                "total_tokens": self._total_tokens,
                "budget_used": self._budget_used,
                "budget_usd": self.budget_usd,
                "consecutive_failures": self._consecutive_failures,
            }

    def _get_key(self) -> str:
        """获取 API Key：传入值 → KeyStore → 环境变量。"""
        if self.api_key:
            return self.api_key
        try:
            from disk_cleaner.db.keystore import KeyStore
            stored = KeyStore().get_key(self.provider_name) or ""
            if stored:
                return stored
        except Exception:
            pass
        env_names = {
            "openai": "OPENAI_API_KEY",
            "claude": "ANTHROPIC_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
            "gemini": "GEMINI_API_KEY",
        }
        return os.environ.get(env_names.get(self.provider_name, ""), "")

    def analyze(self, prompt: str) -> str:
        """发送 prompt；失败时抛 AIUnavailableError，绝不伪造 AI 结果。"""
        if self.provider_name == "local":
            with self._state_lock:
                self._total_calls += 1
            return self._mock_analyze(prompt)

        if not self.api_key:
            self.api_key = self._get_key()

        if self.provider_name in ("openai", "claude", "deepseek", "gemini") and not self.api_key:
            raise AIUnavailableError(f"{self.provider_name} 未配置 API Key")

        with self._state_lock:
            if self.budget_usd > 0 and self._budget_used >= self.budget_usd:
                raise AIUnavailableError(
                    f"AI 预算已用尽（{self._budget_used:.4f}/{self.budget_usd:.4f} USD）"
                )
            if self._consecutive_failures >= 3:
                raise AIUnavailableError("连续多次调用失败，已熔断；请检查网络、Key 或模型名")

        self._rate_limit()
        last_error = ""

        for attempt in range(self.max_retries):
            try:
                result = self._call(prompt)

                if result and result.strip():
                    with self._state_lock:
                        self._total_calls += 1
                        self._consecutive_failures = 0
                    return result
                last_error = "空响应"

            except AIUnavailableError:
                with self._state_lock:
                    self._consecutive_failures += 1
                raise
            except Exception as e:
                last_error = str(e)
                if self._is_non_retryable(e):
                    with self._state_lock:
                        self._consecutive_failures += 1
                    raise AIUnavailableError(
                        f"{self.provider_name} 调用失败（不可重试）: {last_error}"
                    ) from e
                if attempt < self.max_retries - 1:
                    wait = 2 ** attempt  # 指数退避: 1s, 2s, 4s
                    time.sleep(wait)

        with self._state_lock:
            self._consecutive_failures += 1
        raise AIUnavailableError(
            f"{self.provider_name} 调用失败（{self.max_retries} 次重试）: {last_error}"
        )

    def _record_usage(self, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        """记录 token 与按配置费率估算的费用。"""
        prompt_tokens = max(0, int(prompt_tokens or 0))
        completion_tokens = max(0, int(completion_tokens or 0))
        with self._state_lock:
            self._total_tokens += prompt_tokens + completion_tokens
            self._budget_used += (
                prompt_tokens / 1_000_000 * self.input_cost_per_million
                + completion_tokens / 1_000_000 * self.output_cost_per_million
            )

    @staticmethod
    def _is_non_retryable(exc: Exception) -> bool:
        """认证/权限/模型不存在/参数错误无需重试。"""
        name = type(exc).__name__.lower()
        if any(key in name for key in ("authentication", "permissiondenied", "notfound", "badrequest")):
            return True
        status = getattr(exc, "status_code", None)
        if status is None:
            response = getattr(exc, "response", None)
            status = getattr(response, "status_code", None)
        return status in (400, 401, 403, 404)

    def analyze_batch(self, prompts: list[str]) -> list[str]:
        """批量分析，自动速率限制"""
        return [self.analyze(p) for p in prompts]

    def _rate_limit(self) -> None:
        """滑动窗口限流；锁只保护时间表，等待在锁外进行。"""
        while True:
            with self._rate_lock:
                now = time.time()
                cutoff = now - 60
                self._call_times = [t for t in self._call_times if t > cutoff]
                if len(self._call_times) < self.rate_limit_rpm:
                    self._call_times.append(now)
                    return
                wait = self._call_times[0] + 60 - now + 0.5
            if wait > 0:
                time.sleep(wait)

    def _call(self, prompt: str) -> str:
        """默认实现；具体 provider 子类会覆盖。"""
        dispatch = {
            "openai": self._call_openai,
            "ollama": self._call_ollama,
            "claude": self._call_claude,
            "gemini": self._call_gemini,
            "deepseek": self._call_deepseek,
        }
        handler = dispatch.get(self.provider_name)
        if handler is None:
            raise AIUnavailableError(f"未知的 AI 后端: {self.provider_name}")
        return handler(prompt)

    def _call_openai(self, prompt: str) -> str:
        """调用 OpenAI API"""
        try:
            import openai
        except ImportError as e:
            raise AIUnavailableError("openai 未安装") from e
        if not self.api_key:
            raise AIUnavailableError("openai 未配置 API Key")
        client = openai.OpenAI(api_key=self.api_key, timeout=self.timeout_seconds)
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=self.max_output_tokens,
        )
        content = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        if usage is not None:
            self._record_usage(
                getattr(usage, "prompt_tokens", 0),
                getattr(usage, "completion_tokens", 0),
            )
        if not content.strip():
            raise AIUnavailableError("OpenAI 返回空响应")
        return content

    def _call_deepseek(self, prompt: str) -> str:
        """调用 DeepSeek API（兼容 OpenAI SDK）
        模型: deepseek-v4-flash（高性价比）/ deepseek-v4-pro（深度推理）
        """
        try:
            import openai
        except ImportError as e:
            raise AIUnavailableError("openai 未安装") from e

        key = self.api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        if not key:
            raise AIUnavailableError("deepseek 未配置 API Key")

        client = openai.OpenAI(
            api_key=key,
            base_url="https://api.deepseek.com",
            timeout=self.timeout_seconds,
        )
        response = client.chat.completions.create(
            model=self.model or "deepseek-v4-flash",
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=self.max_output_tokens,
        )
        content = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        if usage is not None:
            self._record_usage(
                getattr(usage, "prompt_tokens", 0),
                getattr(usage, "completion_tokens", 0),
            )
        if not content.strip():
            raise AIUnavailableError("DeepSeek 返回空响应")
        return content

    def _call_gemini(self, prompt: str) -> str:
        """调用 Gemini API"""
        try:
            import requests
        except ImportError as e:
            raise AIUnavailableError("requests 未安装") from e

        key = self.api_key or os.environ.get("GEMINI_API_KEY", "")
        if not key:
            raise AIUnavailableError("gemini 未配置 API Key")

        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
            params={"key": key},
            json={
                "contents": [{"parts": [{"text": self.SYSTEM_PROMPT + "\n\n" + prompt}]}],
                "generationConfig": {"temperature": 0.1, "maxOutputTokens": self.max_output_tokens},
            },
            timeout=self.timeout_seconds,
        )
        if resp.status_code != 200:
            raise AIUnavailableError(f"Gemini HTTP {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        usage = data.get("usageMetadata") or {}
        self._record_usage(
            usage.get("promptTokenCount", 0),
            usage.get("candidatesTokenCount", 0),
        )
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as e:
            raise AIUnavailableError("Gemini 响应结构异常") from e
        if not text.strip():
            raise AIUnavailableError("Gemini 返回空响应")
        return text

    def _call_claude(self, prompt: str) -> str:
        """调用 Claude API"""
        try:
            import anthropic
        except ImportError as e:
            raise AIUnavailableError("anthropic 未安装") from e
        if not self.api_key:
            raise AIUnavailableError("claude 未配置 API Key")

        client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout_seconds)
        response = client.messages.create(
            model=self.model,
            max_tokens=self.max_output_tokens,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        usage = getattr(response, "usage", None)
        if usage is not None:
            self._record_usage(
                getattr(usage, "input_tokens", 0),
                getattr(usage, "output_tokens", 0),
            )
        text = response.content[0].text if response.content else ""
        if not text.strip():
            raise AIUnavailableError("Claude 返回空响应")
        return text

    def _call_ollama(self, prompt: str) -> str:
        """调用本地 Ollama 模型"""
        try:
            import requests
        except ImportError as e:
            raise AIUnavailableError("requests 未安装") from e

        try:
            # 快速检测 Ollama 是否在运行（只建连接，不实际推理）
            requests.get("http://localhost:11434/api/tags", timeout=min(2.0, self.timeout_seconds))
        except Exception as e:
            raise AIUnavailableError("Ollama 未运行或不可访问") from e

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": self.max_output_tokens},
            },
            timeout=min(self.timeout_seconds, 60.0),
        )
        if response.status_code != 200:
            raise AIUnavailableError(f"Ollama HTTP {response.status_code}: {response.text[:200]}")
        text = response.json().get("response", "")
        if not text.strip():
            raise AIUnavailableError("Ollama 返回空响应")
        return text

    def _mock_analyze(self, prompt: str) -> str:
        """离线降级分析——基于扩展名和路径的规则推断"""
        p = prompt.lower()

        # === 明确可删 ===
        if any(x in p for x in (".tmp", "~$", ".temp")):
            return json.dumps({"decision": "safe_to_delete", "confidence": 0.95, "reason": "临时文件，程序运行过程中产生的中间数据，关闭后即可删除", "risk": "none"})
        if any(x in p for x in (".dmp", ".mdmp", ".hdmp")):
            return json.dumps({"decision": "safe_to_delete", "confidence": 0.95, "reason": "崩溃转储文件（Dump），程序崩溃时自动生成的调试信息，删除不影响程序运行", "risk": "none"})
        if any(x in p for x in ("\\temp\\", "/tmp/", "\\windows\\temp\\")):
            return json.dumps({"decision": "safe_to_delete", "confidence": 0.92, "reason": "位于系统临时目录，系统和程序不再使用的临时数据", "risk": "none"})
        if "__pycache__" in p or ".pyc" in p:
            return json.dumps({"decision": "safe_to_delete", "confidence": 0.98, "reason": "Python 字节码缓存，Python 运行时会自动重新生成，删除不影响程序", "risk": "none"})
        if ".log" in p:
            return json.dumps({"decision": "likely_safe", "confidence": 0.75, "reason": "日志文件，记录程序运行信息，删除不影响程序功能，但可能丢失问题排查线索", "risk": "low"})
        if any(x in p for x in ("\\cache\\", "\\.cache\\", "\\npm-cache\\", "\\_cacache\\")):
            return json.dumps({"decision": "likely_safe", "confidence": 0.82, "reason": "应用程序缓存，用于加速访问的临时数据，删除后程序会自动重建（首次访问稍慢）", "risk": "low"})
        if ".bak" in p or ".old" in p or ".orig" in p:
            return json.dumps({"decision": "likely_safe", "confidence": 0.80, "reason": "备份文件，通常是软件更新或用户手动创建的副本，确认原文件完好后即可删除", "risk": "low"})

        # === 大概率可删 ===
        if any(x in p for x in (".torrent", ".crdownload", ".partial", ".!ut")):
            return json.dumps({"decision": "likely_safe", "confidence": 0.85, "reason": "未完成的下载文件", "risk": "low"})
        if any(x in p for x in (".thumb", "thumbcache", "iconcache", "thumbnails")):
            return json.dumps({"decision": "safe_to_delete", "confidence": 0.90, "reason": "缩略图缓存", "risk": "none"})

        # === 大概率保留 ===
        if ".dll" in p:
            return json.dumps({"decision": "keep", "confidence": 0.85, "reason": "动态链接库，被一个或多个程序依赖，删除会导致对应程序无法启动", "risk": "high"})
        if ".sys" in p or ".drv" in p:
            return json.dumps({"decision": "keep", "confidence": 0.90, "reason": "系统驱动文件，操作系统或硬件正常工作所必需，切勿删除", "risk": "high"})
        if ".exe" in p:
            return json.dumps({"decision": "keep", "confidence": 0.85, "reason": "可执行程序文件，删除将导致该软件无法使用。如确认已卸载该软件则可删除", "risk": "high"})
        if ".mdf" in p:
            return json.dumps({"decision": "keep", "confidence": 0.95, "reason": "SQL Server 主数据文件（MDF），包含数据库所有表和数据的实体，删除将永久丢失数据且数据库无法恢复", "risk": "high"})
        if ".ldf" in p:
            return json.dumps({"decision": "keep", "confidence": 0.92, "reason": "SQL Server 事务日志文件（LDF），记录所有数据库更改操作，删除可能导致数据库无法恢复", "risk": "high"})
        if ".pst" in p or ".ost" in p:
            return json.dumps({"decision": "keep", "confidence": 0.92, "reason": "Outlook 个人文件夹数据文件，存储邮件、联系人、日历等所有邮箱数据", "risk": "high"})
        if any(x in p for x in (".mdb", ".accdb", ".db3", ".frm", ".ibd", ".myd", ".myi")):
            return json.dumps({"decision": "keep", "confidence": 0.85, "reason": "数据库文件，可能包含重要数据", "risk": "high"})
        if ".vhd" in p or ".vhdx" in p or ".vmdk" in p or ".ova" in p:
            return json.dumps({"decision": "keep", "confidence": 0.90, "reason": "虚拟机磁盘镜像，用户数据", "risk": "high"})
        if ".iso" in p or ".img" in p:
            return json.dumps({"decision": "keep", "confidence": 0.78, "reason": "磁盘镜像，可能为系统安装盘", "risk": "medium"})
        if any(x in p for x in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf")):
            return json.dumps({"decision": "keep", "confidence": 0.80, "reason": "文档文件，用户数据", "risk": "medium"})
        if any(x in p for x in (".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mov", ".avi", ".mp3")):
            return json.dumps({"decision": "keep", "confidence": 0.80, "reason": "媒体文件，用户数据", "risk": "medium"})
        if any(x in p for x in (".pem", ".key", ".crt", ".cer", ".pfx", ".p12", ".kdbx")):
            return json.dumps({"decision": "keep", "confidence": 0.95, "reason": "证书/密钥文件，不应删除", "risk": "high"})
        if ".sqlite" in p or ".sqlite3" in p or ".db" in p:
            return json.dumps({"decision": "needs_review", "confidence": 0.55, "reason": "SQLite 数据库，可能为应用数据或缓存", "risk": "medium"})

        # === 路径启发式 ===
        if "\\program files\\" in p or "\\program files (x86)\\" in p:
            return json.dumps({"decision": "keep", "confidence": 0.75, "reason": "位于 Program Files，可能为已安装软件", "risk": "medium"})
        if "\\appdata\\local\\" in p or "\\appdata\\roaming\\" in p:
            return json.dumps({"decision": "likely_safe", "confidence": 0.65, "reason": "位于 AppData，可能为应用数据", "risk": "medium"})
        if "\\documents\\" in p and not any(x in p for x in (".txt", ".doc", ".pdf")):
            return json.dumps({"decision": "needs_review", "confidence": 0.50, "reason": "位于文档目录但非文档类型，需确认", "risk": "medium"})

        # === 内容摘要智能判断（profiler 已读取文件）===
        if "文件类型: config" in p:
            if "含敏感字段" in p:
                return json.dumps({"decision": "keep", "confidence": 0.95, "reason": "配置文件包含敏感字段（如 password/token/key），删除可能导致程序认证失败", "risk": "high"})
            return json.dumps({"decision": "keep", "confidence": 0.78, "reason": "配置文件，通常存储程序设置参数，删除后程序可能恢复默认设置或无法启动", "risk": "medium"})
        if "文件类型: text_log" in p or "文件类型: log" in p:
            err_match = re.search(r"含\s*(\d+)\s*条\s*ERROR", p)
            if err_match:
                return json.dumps({"decision": "likely_safe", "confidence": 0.75, "reason": f"日志文件，含 {err_match.group(1)} 条 ERROR（可能为已修复的历史错误），通常可安全清理", "risk": "low"})
            return json.dumps({"decision": "likely_safe", "confidence": 0.68, "reason": "日志文件，仅记录程序运行信息，删除不影响程序功能", "risk": "low"})
        if "文件类型: sqlite" in p:
            tbl_match = re.search(r"数据库表:\s*(.+)", p)
            tbl_info = f"（{tbl_match.group(1)}）" if tbl_match else ""
            if "cache" in p:
                return json.dumps({"decision": "likely_safe", "confidence": 0.75, "reason": f"SQLite 缓存数据库{tbl_info}，存储临时数据，删除后程序会自动重建", "risk": "low"})
            return json.dumps({"decision": "needs_review", "confidence": 0.55, "reason": f"SQLite 数据库{tbl_info}，可能存储应用数据，建议确认用途后再处理", "risk": "medium"})
        if "字段数:" in p:
            fc_match = re.search(r"字段数:\s*(\d+)", p)
            fc_info = f"（含 {fc_match.group(1)} 个字段）" if fc_match else ""
            return json.dumps({"decision": "keep", "confidence": 0.70, "reason": f"结构化数据文件{fc_info}，可能为应用数据，建议确认后处理", "risk": "medium"})

        # === 兜底 ===
        return json.dumps({"decision": "needs_review", "confidence": 0.40, "reason": "无法根据文件名和路径自动判断", "risk": "unknown"})


class LocalProvider(AIProvider):
    def __init__(self, api_key: str = "", model: str = "", **kwargs):
        super().__init__("local", api_key=api_key, model=model, **kwargs)

    def _call(self, prompt: str) -> str:
        return self._mock_analyze(prompt)


class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str = "", model: str = "", **kwargs):
        super().__init__("openai", api_key=api_key, model=model, **kwargs)

    def _call(self, prompt: str) -> str:
        return self._call_openai(prompt)


class DeepSeekProvider(AIProvider):
    def __init__(self, api_key: str = "", model: str = "", **kwargs):
        super().__init__("deepseek", api_key=api_key, model=model, **kwargs)

    def _call(self, prompt: str) -> str:
        return self._call_deepseek(prompt)


class ClaudeProvider(AIProvider):
    def __init__(self, api_key: str = "", model: str = "", **kwargs):
        super().__init__("claude", api_key=api_key, model=model, **kwargs)

    def _call(self, prompt: str) -> str:
        return self._call_claude(prompt)


class GeminiProvider(AIProvider):
    def __init__(self, api_key: str = "", model: str = "", **kwargs):
        super().__init__("gemini", api_key=api_key, model=model, **kwargs)

    def _call(self, prompt: str) -> str:
        return self._call_gemini(prompt)


class OllamaProvider(AIProvider):
    def __init__(self, api_key: str = "", model: str = "", **kwargs):
        super().__init__("ollama", api_key=api_key, model=model, **kwargs)

    def _call(self, prompt: str) -> str:
        return self._call_ollama(prompt)
