"""AI 客户端——统一接口层，含重试、速率限制、降级"""

import json
import os
import re
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


def parse_ai_response(text: str, is_cluster: bool = False) -> FileAnalysisOutput:
    """从 AI 响应文本中解析分析结果"""
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
    else:
        # 可能只是纯文本响应
        pass

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return FileAnalysisOutput(
            decision="needs_review",
            confidence=0.30,
            reason=f"AI 响应格式异常，无法解析: {text[:200]}",
            risk="unknown",
        )

    if is_cluster:
        return FileAnalysisOutput(
            decision=data.get("cluster_decision", "needs_review"),
            confidence=0.80,
            reason=data.get("cluster_reason", ""),
            total_reclaimable_mb=data.get("total_reclaimable_mb", 0.0),
            warnings=data.get("warnings", []),
        )

    return FileAnalysisOutput(
        decision=data.get("decision", "needs_review"),
        confidence=float(data.get("confidence", 0.5)),
        reason=data.get("reason", ""),
        risk=data.get("risk", "unknown"),
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


class AIProvider:
    """AI 后端统一接口——含重试、速率限制、降级"""

    SYSTEM_PROMPT = (
        "你是一个磁盘清理专家。根据文件路径、大小、类型、修改时间等信息，"
        "判断文件是否可以安全删除。只返回 JSON，不要有其他内容。"
    )

    def __init__(self, provider_name: str, api_key: str = "", model: str = "",
                 max_retries: int = 3, rate_limit_rpm: int = 30, **kwargs):
        self.provider_name = provider_name
        self.api_key = api_key
        self.model = model
        self.kwargs = kwargs
        self.max_retries = max_retries
        self.rate_limit_rpm = rate_limit_rpm
        self._call_times: list[float] = []
        self._total_calls = 0
        self._total_tokens = 0
        self._budget_used = 0.0

    @classmethod
    def create(cls, provider: str, api_key: str = "", model: str = "", **kwargs) -> "AIProvider":
        """工厂方法"""
        supported = ("openai", "claude", "ollama", "gemini", "deepseek", "local")
        if provider not in supported:
            raise ValueError(f"不支持的 AI 后端: {provider}，支持: {', '.join(supported)}")
        return cls(provider_name=provider, api_key=api_key, model=model, **kwargs)

    @property
    def stats(self) -> dict:
        return {
            "total_calls": self._total_calls,
            "total_tokens": self._total_tokens,
            "budget_used": self._budget_used,
        }

    def _get_key(self) -> str:
        """获取 API Key：优先用传入的，否则从 KeyStore 读取"""
        if self.api_key:
            return self.api_key
        try:
            from disk_cleaner.db.keystore import KeyStore
            return KeyStore().get_key(self.provider_name) or ""
        except Exception:
            return ""

    def analyze(self, prompt: str) -> str:
        """发送 prompt，带重试和速率限制"""
        if not self.api_key:
            self.api_key = self._get_key()

        self._rate_limit()
        last_error = ""

        for attempt in range(self.max_retries):
            try:
                if self.provider_name == "local":
                    result = self._mock_analyze(prompt)
                elif self.provider_name == "openai":
                    result = self._call_openai(prompt)
                elif self.provider_name == "ollama":
                    result = self._call_ollama(prompt)
                elif self.provider_name == "claude":
                    result = self._call_claude(prompt)
                elif self.provider_name == "gemini":
                    result = self._call_gemini(prompt)
                elif self.provider_name == "deepseek":
                    result = self._call_deepseek(prompt)
                else:
                    result = self._mock_analyze(prompt)

                if result:
                    self._total_calls += 1
                    return result

            except Exception as e:
                last_error = str(e)
                if attempt < self.max_retries - 1:
                    wait = 2 ** attempt  # 指数退避: 1s, 2s, 4s
                    time.sleep(wait)

        # 所有重试失败，降级
        return json.dumps({
            "decision": "needs_review",
            "confidence": 0.0,
            "reason": f"API 调用失败（{self.max_retries} 次重试）: {last_error}",
            "risk": "unknown",
        })

    def analyze_batch(self, prompts: list[str]) -> list[str]:
        """批量分析，自动速率限制"""
        return [self.analyze(p) for p in prompts]

    def _rate_limit(self) -> None:
        """速率限制：确保不超过 rate_limit_rpm 次/分钟"""
        now = time.time()
        cutoff = now - 60
        self._call_times = [t for t in self._call_times if t > cutoff]

        if len(self._call_times) >= self.rate_limit_rpm:
            oldest = self._call_times[0]
            wait = oldest + 60 - now + 0.5
            if wait > 0:
                time.sleep(wait)

        self._call_times.append(now)

    def _call_openai(self, prompt: str) -> str:
        """调用 OpenAI API"""
        import openai
        client = openai.OpenAI(api_key=self.api_key)
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=300,
        )
        content = response.choices[0].message.content or ""
        # 估算 token 和费用
        if hasattr(response, "usage"):
            self._total_tokens += response.usage.total_tokens
            # GPT-4o-mini: ~$0.15/1M input, ~$0.60/1M output
            if "4o-mini" in self.model:
                cost = response.usage.prompt_tokens * 0.15 / 1_000_000
                cost += response.usage.completion_tokens * 0.60 / 1_000_000
                self._budget_used += cost
        return content

    def _call_deepseek(self, prompt: str) -> str:
        """调用 DeepSeek API（兼容 OpenAI SDK）
        模型: deepseek-v4-flash（高性价比）/ deepseek-v4-pro（深度推理）
        """
        import openai

        key = self.api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        if not key:
            return self._mock_analyze(prompt)

        client = openai.OpenAI(
            api_key=key,
            base_url="https://api.deepseek.com",
        )
        response = client.chat.completions.create(
            model=self.model or "deepseek-v4-flash",
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=300,
        )
        return response.choices[0].message.content or ""

    def _call_gemini(self, prompt: str) -> str:
        """调用 Gemini API"""
        try:
            import requests
            key = self.api_key or os.environ.get("GEMINI_API_KEY", "")
            if not key:
                return self._mock_analyze(prompt)
            resp = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
                params={"key": key},
                json={
                    "contents": [{"parts": [{"text": self.SYSTEM_PROMPT + "\n\n" + prompt}]}],
                    "generationConfig": {"temperature": 0.1, "maxOutputTokens": 300},
                },
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            return self._mock_analyze(prompt)
        except Exception:
            return self._mock_analyze(prompt)

    def _call_claude(self, prompt: str) -> str:
        """调用 Claude API"""
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.model,
                max_tokens=300,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        except ImportError:
            return self._mock_analyze(prompt)

    def _call_ollama(self, prompt: str) -> str:
        """调用本地 Ollama 模型"""
        import requests
        try:
            # 快速检测 Ollama 是否在运行（只建连接，不实际推理）
            requests.get("http://localhost:11434/api/tags", timeout=1)
        except Exception:
            return self._mock_analyze(prompt)
        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=5,
            )
            if response.status_code == 200:
                return response.json().get("response", "")
        except Exception:
            pass
        return self._mock_analyze(prompt)

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
