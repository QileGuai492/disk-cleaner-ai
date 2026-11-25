"""结构化分析结果测试。"""

import json

from disk_cleaner.analyzer.result import AnalysisResult


def _sample(**overrides):
    data = dict(
        path="C:\\Temp\\a.tmp",
        name="a.tmp",
        size=100,
        size_mb=0.0,
        extension=".tmp",
        mtime=1700000000.0,
        decision="safe_to_delete",
        confidence=0.95,
        reason="临时文件",
        risk="none",
        source="rule",
        cached=False,
    )
    data.update(overrides)
    return AnalysisResult(**data)


def test_dict_compatibility_and_properties():
    result = _sample()
    assert result["decision"] == "safe_to_delete"
    assert result.get("source") == "rule"
    assert result.decision == "safe_to_delete"
    assert result.path.endswith("a.tmp")
    assert result.cached is False


def test_json_serializable():
    result = _sample(cached=True, source="ai+cache")
    payload = json.dumps(result, ensure_ascii=False)
    assert "safe_to_delete" in payload
    assert "ai+cache" in payload


def test_from_dict_and_to_dict():
    result = _sample()
    roundtrip = AnalysisResult.from_dict(result.to_dict())
    assert roundtrip["path"] == result["path"]
    assert roundtrip.confidence == 0.95
    assert roundtrip.cached is False
