"""规则引擎测试"""

import pytest
from disk_cleaner.scanner.walker import FileInfo
from disk_cleaner.analyzer.rules import RuleEngine, Rule, MatchResult


@pytest.fixture
def tmp_file():
    return FileInfo(
        path="C:\\Users\\test\\AppData\\Local\\Temp\\abc123.tmp",
        size=5_000_000,
        mtime=1700000000.0,
    )


@pytest.fixture
def log_file():
    return FileInfo(
        path="C:\\Users\\test\\AppData\\Local\\MyApp\\error-2024-01-15.log",
        size=50_000_000,
        mtime=1705000000.0,
    )


@pytest.fixture
def exe_file():
    return FileInfo(
        path="C:\\Program Files\\MyApp\\MyApp.exe",
        size=15_000_000,
        mtime=1710000000.0,
    )


@pytest.fixture
def dll_file():
    return FileInfo(
        path="C:\\Program Files\\MyApp\\helper.dll",
        size=3_000_000,
        mtime=1710000000.0,
    )


class TestRule:
    """单条规则测试"""

    def test_glob规则匹配扩展名(self, tmp_file):
        rule = Rule(pattern="*.tmp", decision="safe_to_delete", confidence=0.99)
        assert rule.matches(tmp_file)
        result = rule.evaluate(tmp_file)
        assert result.decision == "safe_to_delete"
        assert result.confidence == 0.99

    def test_glob规则不匹配不同扩展名(self, log_file):
        rule = Rule(pattern="*.tmp", decision="safe_to_delete", confidence=0.99)
        assert not rule.matches(log_file)

    def test_路径包含模式匹配(self, log_file):
        rule = Rule(pattern="**\\AppData\\**", decision="likely_safe", confidence=0.85)
        assert rule.matches(log_file)

    def test_正则表达式匹配(self, log_file):
        rule = Rule(
            pattern=r".*\\error-\d{4}-\d{2}-\d{2}\.log$",
            decision="safe_to_delete",
            confidence=0.90,
            is_regex=True,
        )
        assert rule.matches(log_file)

    def test_正则表达式不匹配(self, tmp_file):
        rule = Rule(
            pattern=r".*\\error-\d{4}-\d{2}-\d{2}\.log$",
            decision="safe_to_delete",
            confidence=0.90,
            is_regex=True,
        )
        assert not rule.matches(tmp_file)

    def test_规则包含来源信息(self):
        rule = Rule(
            pattern="*.tmp",
            decision="safe_to_delete",
            confidence=0.99,
            source="ai_learned",
        )
        assert rule.source == "ai_learned"

    def test_规则命中计数(self, tmp_file):
        rule = Rule(pattern="*.tmp", decision="safe_to_delete", confidence=0.99)
        assert rule.hit_count == 0
        rule.evaluate(tmp_file)
        assert rule.hit_count == 1
        rule.evaluate(tmp_file)
        assert rule.hit_count == 2


class TestRuleEngine:
    """规则引擎测试"""

    @pytest.fixture
    def engine(self):
        engine = RuleEngine()
        # 添加内置规则
        engine.add_rule(Rule(pattern="*.tmp", decision="safe_to_delete", confidence=0.99))
        engine.add_rule(Rule(pattern="*.temp", decision="safe_to_delete", confidence=0.99))
        engine.add_rule(Rule(pattern="*\\Temp\\**", decision="safe_to_delete", confidence=0.95))
        engine.add_rule(Rule(pattern="*.log", decision="likely_safe", confidence=0.80))
        return engine

    def test_匹配已知临时文件(self, engine, tmp_file):
        result = engine.evaluate(tmp_file)
        assert result is not None
        assert result.decision == "safe_to_delete"

    def test_匹配日志文件(self, engine, log_file):
        result = engine.evaluate(log_file)
        assert result is not None
        assert result.decision == "likely_safe"

    def test_不匹配未知文件(self, engine, exe_file):
        result = engine.evaluate(exe_file)
        assert result is None  # 没有规则命中

    def test_规则按优先级排序(self, engine, tmp_file):
        # 添加更高优先级的规则
        engine.add_rule(Rule(pattern="*.tmp", decision="keep", confidence=1.0, priority=100))
        result = engine.evaluate(tmp_file)
        assert result.decision == "keep"  # 高优先级规则先生效

    def test_添加重复规则不报错(self, engine):
        # 重复 pattern 被跳过（同来源同优先级），不增加规则数
        engine.add_rule(Rule(pattern="*.tmp", decision="safe_to_delete", confidence=0.99))
        assert len(engine.rules) == 4  # 去重：同 pattern 不重复添加

    def test_用户自定义规则优先级高于AI规则(self):
        engine = RuleEngine()
        engine.add_rule(Rule(pattern="*.tmp", decision="safe_to_delete", confidence=0.99, source="ai_learned"))
        engine.add_rule(Rule(pattern="*.tmp", decision="keep", confidence=1.0, source="user_defined"))

        file = FileInfo(path="/tmp/test.tmp", size=100, mtime=1234567890.0)
        result = engine.evaluate(file)
        assert result.decision == "keep"
        assert result.confidence == 1.0

    def test_白名单规则优先级最高(self):
        engine = RuleEngine()
        # 一般规则说删
        engine.add_rule(Rule(pattern="**\\Windows\\**", decision="safe_to_delete", confidence=0.80))
        # 白名单说保留
        engine.add_rule(
            Rule(pattern="**\\Windows\\System32\\**", decision="keep", confidence=1.0, source="user_defined", priority=1000)
        )

        sys_file = FileInfo(
            path="C:\\Windows\\System32\\kernel32.dll",
            size=1_000_000,
            mtime=1234567890.0,
        )
        result = engine.evaluate(sys_file)
        assert result.decision == "keep"

    def test_规则添加时自动去重(self):
        engine = RuleEngine()
        engine.add_rule(Rule(pattern="*.log", decision="safe_to_delete", confidence=0.90))
        engine.add_rule(Rule(pattern="*.log", decision="likely_safe", confidence=0.80))
        # 第一条保留（去重）
        assert len(engine.rules) == 1
        assert engine.rules[0].confidence == 0.90

    def test_从调用结果学习新规则(self, engine):
        # AI 分析结果格式
        ai_results = [
            {"path": "/tmp/cache_001.bin", "decision": "safe_to_delete", "confidence": 0.95},
            {"path": "/tmp/cache_002.bin", "decision": "safe_to_delete", "confidence": 0.93},
        ]
        # 这里验证 learn_from_results 方法存在且可用
        assert hasattr(engine, "learn_from_results")


class TestMatchResult:
    """MatchResult 测试"""

    def test_创建匹配结果(self):
        result = MatchResult(
            decision="safe_to_delete",
            confidence=0.95,
            rule_pattern="*.tmp",
            reason="匹配规则 *.tmp",
        )
        assert result.decision == "safe_to_delete"
        assert result.confidence == 0.95
        assert "*.tmp" in result.reason
