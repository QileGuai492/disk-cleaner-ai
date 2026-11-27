"""统一配置测试。"""

import json

import pytest

from disk_cleaner.config import (
    AppConfig,
    ConfigError,
    ensure_default_config,
    get_config_path,
    load_config,
    save_config,
)


def test_defaults():
    config = AppConfig()
    assert config.gui.port == 8765
    assert config.backup.retention_days == 30
    assert config.scan.max_dirs == 5000
    assert ".env" in config.privacy.extension_blocklist
    assert config.log.level == "INFO"


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "config.json"
    config = AppConfig()
    config.gui.port = 9000
    config.backup.retention_days = 7
    config.scan.max_dirs = 1200
    config.ai.timeout_seconds = 12
    config.ai.max_output_tokens = 2048
    config.ai.budget_usd = 1.5
    config.ai.input_cost_per_million = 0.15
    config.ai.cloud_blocklist = ["*\\Documents\\*"]
    save_config(config, str(path))

    loaded = load_config(str(path))
    assert loaded.gui.port == 9000
    assert loaded.backup.retention_days == 7
    assert loaded.scan.max_dirs == 1200
    assert loaded.ai.timeout_seconds == 12
    assert loaded.ai.max_output_tokens == 2048
    assert loaded.ai.budget_usd == 1.5
    assert loaded.ai.input_cost_per_million == 0.15
    assert loaded.ai.cloud_blocklist == ["*\\Documents\\*"]


def test_partial_config_keeps_defaults(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"gui": {"port": 9999}}), encoding="utf-8")
    config = load_config(str(path))
    assert config.gui.port == 9999
    assert config.gui.open_browser is True
    assert config.backup.retention_days == 30


def test_invalid_json_raises(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(path))


def test_utf8_bom_config(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"backup": {"retention_days": 14}}),
        encoding="utf-8-sig",
    )
    assert load_config(str(path)).backup.retention_days == 14


def test_ensure_default_config(tmp_path):
    path = tmp_path / "nested" / "config.json"
    created = ensure_default_config(str(path))
    assert created == path
    assert path.exists()
    assert load_config(str(path)).gui.port == 8765


def test_env_config_path(monkeypatch, tmp_path):
    target = tmp_path / "via-env.json"
    monkeypatch.setenv("DISK_CLEANER_CONFIG", str(target))
    assert get_config_path() == target
