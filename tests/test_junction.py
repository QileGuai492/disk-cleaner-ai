"""Junction 搬迁的回滚与安全行为测试（不实际创建系统链接）。"""

import pytest

from disk_cleaner.cleaner.junction import JunctionManager


@pytest.fixture
def source_dir(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.txt").write_text("important", encoding="utf-8")
    return source


def test_create_refuses_non_empty_source(source_dir, tmp_path):
    target = tmp_path / "target"
    target.mkdir()

    result = JunctionManager.create(str(source_dir), str(target))
    assert not result.success
    assert "源目录非空" in result.error
    assert (source_dir / "data.txt").exists()


def test_create_replaces_empty_source(monkeypatch, tmp_path):
    source = tmp_path / "empty_source"
    source.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr(
        JunctionManager, "_create_link", staticmethod(lambda source, target: (True, ""))
    )

    result = JunctionManager.create(str(source), str(target))
    assert result.success
    assert not source.exists()


def test_relocate_rolls_back_when_link_fails(monkeypatch, source_dir, tmp_path):
    target_base = tmp_path / "relocated"
    target_base.mkdir()
    monkeypatch.setattr(
        JunctionManager,
        "_create_link",
        staticmethod(lambda source, target: (False, "mklink failed")),
    )

    result = JunctionManager.relocate_directory(str(source_dir), str(target_base))
    assert not result.success
    assert "已回滚" in result.error
    assert (source_dir / "data.txt").exists()
    assert not (target_base / "source").exists()


def test_relocate_success_moves_source(monkeypatch, source_dir, tmp_path):
    target_base = tmp_path / "relocated"
    target_base.mkdir()
    monkeypatch.setattr(
        JunctionManager, "_create_link", staticmethod(lambda source, target: (True, ""))
    )

    result = JunctionManager.relocate_directory(str(source_dir), str(target_base))
    assert result.success
    assert not source_dir.exists()
    assert (target_base / "source" / "data.txt").exists()


def test_normal_directory_is_not_junction(tmp_path):
    normal = tmp_path / "normal"
    normal.mkdir()
    assert not JunctionManager.is_junction(str(normal))
