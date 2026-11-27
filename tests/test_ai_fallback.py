"""AI 不可用时的显式降级与响应校验测试。"""

import json
import os

import pytest

from disk_cleaner.analyzer.ai_client import (
    AIProvider,
    AIUnavailableError,
    parse_ai_response,
)
from disk_cleaner.analyzer.engine import AnalysisEngine
from disk_cleaner.analyzer.rules import RuleEngine
from disk_cleaner.db.models import Database


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "test.db"))
    database.initialize()
    yield database
    database.close()


def test_cloud_provider_without_key_fails_fast():
    provider = AIProvider.create("deepseek", api_key="", model="deepseek-v4-flash")
    provider._get_key = lambda: ""
    with pytest.raises(AIUnavailableError, match="未配置 API Key"):
        provider.analyze("test")


def test_openai_without_key_fails_fast():
    provider = AIProvider.create("openai", api_key="", model="gpt-4o-mini")
    provider._get_key = lambda: ""
    with pytest.raises(AIUnavailableError, match="未配置 API Key"):
        provider.analyze("test")


def test_unknown_decision_is_downgraded():
    result = parse_ai_response(
        json.dumps({"decision": "delete_everything", "confidence": 2.0, "reason": "x"})
    )
    assert result.decision == "needs_review"
    assert result.confidence == 1.0


def test_null_confidence_does_not_crash():
    result = parse_ai_response(
        json.dumps({"decision": "keep", "confidence": None, "reason": "x"})
    )
    assert result.decision == "keep"
    assert result.confidence == 0.5


def test_non_object_json_is_rejected():
    result = parse_ai_response("[1, 2, 3]")
    assert result.decision == "needs_review"
    assert "不是 JSON 对象" in result.reason


def test_truncated_json_keeps_decision():
    result = parse_ai_response(
        '{"decision": "keep", "confidence": 0.9, "reason": "这里是被截断的理由'
    )
    assert result.decision == "keep"
    assert result.confidence == 0.9


def test_engine_marks_degraded_and_does_not_cache(tmp_path, db):
    target = tmp_path / "unknown.xyz"
    target.write_text("binary-ish", encoding="utf-8")

    engine = AnalysisEngine(db, ai_provider="deepseek", ai_model="deepseek-v4-flash")
    engine.rules = RuleEngine()
    engine._ai = AIProvider.create("deepseek", api_key="", model="deepseek-v4-flash")
    engine._ai._get_key = lambda: ""
    results = engine.analyze_path(str(target))
    assert results[0]["source"] == "degraded"
    assert "AI 不可用" in results[0]["reason"]
    assert engine.stats["degraded"] == 1

    # 降级结果不能写入 AI 缓存
    count = db._conn.execute(
        "SELECT COUNT(*) FROM analysis_cache WHERE file_path=?", (os.path.abspath(str(target)),)
    ).fetchone()[0]
    assert count == 0


def test_blocked_extension_never_calls_cloud(tmp_path, db):
    target = tmp_path / ".env"
    target.write_text("SECRET_KEY=abc", encoding="utf-8")

    engine = AnalysisEngine(db, ai_provider="deepseek", ai_model="deepseek-v4-flash")
    engine.rules = RuleEngine()

    class Boom:
        def analyze(self, prompt):
            raise AssertionError("blocked file must not reach cloud")

    engine._ai = Boom()
    results = engine.analyze_path(str(target))
    assert results[0]["source"] == "local"
    assert "禁止上传" in results[0]["reason"]


def test_cloud_prompt_is_anonymized(tmp_path, db):
    folder = tmp_path / "Users" / "alice"
    folder.mkdir(parents=True)
    target = folder / "app.log"
    target.write_text("ERROR something", encoding="utf-8")

    engine = AnalysisEngine(db, ai_provider="deepseek", ai_model="deepseek-v4-flash")
    engine.rules = RuleEngine()
    captured = {}

    class Capture:
        def analyze(self, prompt):
            captured["prompt"] = prompt
            return json.dumps({
                "decision": "likely_safe",
                "confidence": 0.8,
                "reason": "日志",
                "risk": "low",
            })

    engine._ai = Capture()
    results = engine.analyze_path(str(target))
    assert results[0]["source"] == "ai"
    assert "alice" not in captured["prompt"]
    assert "<USER>" in captured["prompt"]
