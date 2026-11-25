"""AI 客户端测试"""

import json

import pytest
from disk_cleaner.analyzer.ai_client import (
    AIProvider,
    AIUnavailableError,
    OpenAIProvider,
    OllamaProvider,
    FileAnalysisInput,
    FileAnalysisOutput,
    parse_ai_response,
    build_single_file_prompt,
    build_cluster_prompt,
)


class TestFileAnalysisInput:
    """分析输入数据类测试"""

    def test_构建单文件输入(self):
        inp = FileAnalysisInput(
            path="/tmp/test.tmp",
            size_mb=100.0,
            extension=".tmp",
            last_modified="2024-01-15",
            path_keywords=["tmp", "temp"],
            analysis_round=1,
        )
        assert inp.size_mb == 100.0
        assert inp.extension == ".tmp"
        assert inp.analysis_round == 1
        assert inp.content_summary is None

    def test_构建含内容摘要的输入(self):
        inp = FileAnalysisInput(
            path="/tmp/data.db",
            size_mb=340.0,
            extension=".db",
            last_modified="2023-08-01",
            path_keywords=["AppData", "Local"],
            analysis_round=2,
            content_summary={"file_type": "sqlite", "tables": ["cache_entries"], "row_count": 537},
        )
        assert inp.analysis_round == 2
        assert inp.content_summary["file_type"] == "sqlite"


class TestFileAnalysisOutput:
    """分析输出数据类测试"""

    def test_解析标准输出(self):
        out = FileAnalysisOutput(
            decision="safe_to_delete",
            confidence=0.95,
            reason="可以安全删除",
            risk="none",
        )
        assert out.decision == "safe_to_delete"
        assert out.is_actionable  # 可以直接行动

    def test_needs_review需要用户介入(self):
        out = FileAnalysisOutput(decision="needs_review", confidence=0.50, reason="", risk="medium")
        assert not out.is_actionable

    def test_keep和critical不可删除(self):
        for decision in ("keep", "critical"):
            out = FileAnalysisOutput(decision=decision, confidence=1.0, reason="", risk="high")
            assert not out.is_actionable


class TestParseAIResponse:
    """AI 响应解析测试"""

    def test_解析标准JSON响应(self):
        response = json.dumps({
            "decision": "safe_to_delete",
            "confidence": 0.95,
            "reason": "临时文件",
            "risk": "none",
        })
        result = parse_ai_response(response)
        assert result.decision == "safe_to_delete"
        assert result.confidence == 0.95

    def test_处理JSON外的文本_从代码块提取(self):
        response = """这是一些前言文字
```json
{"decision": "safe_to_delete", "confidence": 0.90, "reason": "测试", "risk": "none"}
```
一些后记"""
        result = parse_ai_response(response)
        assert result.decision == "safe_to_delete"
        assert result.confidence == 0.90

    def test_无效JSON返回默认值(self):
        result = parse_ai_response("这不是有效的 JSON")
        assert result.decision == "needs_review"
        assert result.confidence < 0.5

    def test_空响应返回默认值(self):
        result = parse_ai_response("")
        assert result.decision == "needs_review"

    def test_解析组合分析响应(self):
        response = json.dumps({
            "cluster_decision": "safe_to_delete",
            "cluster_reason": "整体可清理",
            "total_reclaimable_mb": 2575,
            "files": [
                {"name": "a.exe", "decision": "safe_to_delete"},
                {"name": "b.dll", "decision": "safe_to_delete"},
            ],
            "warnings": ["建议备份存档"],
        })
        result = parse_ai_response(response, is_cluster=True)
        assert result.decision == "safe_to_delete"
        assert result.total_reclaimable_mb == 2575


class TestBuildPrompts:
    """Prompt 构建测试"""

    def test_单文件prompt包含必要信息(self):
        inp = FileAnalysisInput(
            path="C:\\Users\\test\\Temp\\file.tmp",
            size_mb=50.0,
            extension=".tmp",
            last_modified="2024-01-15",
            path_keywords=["Users", "test", "Temp"],
        )
        prompt = build_single_file_prompt(inp)
        assert "file.tmp" in prompt
        assert ".tmp" in prompt
        assert "50.0" in prompt
        assert "2024-01-15" in prompt

    def test_聚类prompt包含文件列表(self):
        files = [
            FileAnalysisInput(
                path="D:\\Games\\OldGame\\OldGame.exe",
                size_mb=45.0,
                extension=".exe",
                last_modified="2022-03-10",
                path_keywords=["Games", "OldGame"],
            ),
            FileAnalysisInput(
                path="D:\\Games\\OldGame\\data.pak",
                size_mb=2100.0,
                extension=".pak",
                last_modified="2022-03-10",
                path_keywords=["Games", "OldGame"],
            ),
        ]
        prompt = build_cluster_prompt(
            cluster_type="same_directory",
            cluster_label="D:\\Games\\OldGame\\",
            total_size_mb=2145.0,
            files=files,
        )
        assert "OldGame.exe" in prompt
        assert "data.pak" in prompt
        assert "2145.0" in prompt


class TestAIProvider:
    """AI Provider 基类测试"""

    def test_从配置构建OpenAI(self):
        provider = AIProvider.create("openai", api_key="sk-test", model="gpt-4o-mini")
        assert isinstance(provider, OpenAIProvider)
        assert provider.provider_name == "openai"
        assert provider.model == "gpt-4o-mini"

    def test_从配置构建Claude(self):
        provider = AIProvider.create("claude", api_key="sk-ant-test", model="claude-haiku")
        assert provider.provider_name == "claude"

    def test_不支持的后端抛出异常(self):
        with pytest.raises(ValueError, match="不支持"):
            AIProvider.create("unsupported", api_key="")

    def test_ollama不需要api_key(self):
        provider = AIProvider.create("ollama", model="qwen2.5:1.5b")
        assert isinstance(provider, OllamaProvider)
        assert provider.provider_name == "ollama"

    def test_预算用尽时快速失败(self):
        provider = AIProvider.create("openai", api_key="sk-test", budget_usd=0.01)
        provider._budget_used = 0.02
        with pytest.raises(AIUnavailableError, match="预算"):
            provider.analyze("test")

    def test_连续失败熔断(self):
        provider = AIProvider.create("openai", api_key="sk-test")
        provider._consecutive_failures = 3
        with pytest.raises(AIUnavailableError, match="熔断"):
            provider.analyze("test")

    def test_按费率记录用量(self):
        provider = AIProvider.create(
            "openai",
            api_key="sk-test",
            input_cost_per_million=1.0,
            output_cost_per_million=2.0,
        )
        provider._record_usage(1_000_000, 500_000)
        assert provider.stats["total_tokens"] == 1_500_000
        assert provider.stats["budget_used"] == pytest.approx(2.0)

    def test_timeout_有下限(self):
        provider = AIProvider.create("openai", api_key="sk-test", timeout_seconds=0.1)
        assert provider.timeout_seconds >= 1.0
