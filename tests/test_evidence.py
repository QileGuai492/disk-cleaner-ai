"""证据层测试：应用名、角色、关联组、文件夹评估。"""

from disk_cleaner.analyzer.evidence import (
    EvidenceBook,
    FolderAssessor,
    RelatedGroupDetector,
    app_key,
    classify_role,
)


def _result(path, decision="needs_review", size=1000, mtime=1700000000.0, reason=""):
    return {
        "path": path,
        "name": path.rsplit("/", 1)[-1],
        "size": size,
        "size_mb": size / 1024 / 1024,
        "mtime": mtime,
        "decision": decision,
        "confidence": 0.8,
        "reason": reason,
        "source": "ai",
    }


def test_app_key_across_known_roots():
    assert app_key("D:/Games/OldGame/OldGame.exe") == "OldGame"
    assert app_key("C:/Program Files/OldApp/app.exe") == "OldApp"
    assert app_key("C:/Users/alice/AppData/Local/OldGame/cache/a.bin") == "OldGame"
    assert app_key("C:/Users/alice/Documents/OldGame/save.dat") == "OldGame"


def test_classify_role_does_not_mistake_catalog_for_log():
    assert classify_role("C:/App/catalog.json") == "config"
    assert classify_role("C:/Users/alice/AppData/Local/Temp/a.tmp") == "cache"
    assert classify_role("C:/Users/alice/Documents/report.docx") == "user_data"
    assert classify_role("C:/Program Files/App/app.exe") == "program"
    assert classify_role("D:/Projects/demo/build.gradle") == "config"


def test_related_groups_oldgame():
    results = [
        _result("D:/Games/OldGame/OldGame.exe", "keep", 45_000_000),
        _result("C:/Users/alice/AppData/Local/OldGame/cache/data.bin", "safe_to_delete", 180_000_000),
        _result("C:/Users/alice/Documents/OldGame/save.dat", "keep", 45_000),
    ]
    groups = RelatedGroupDetector().build(results)
    assert groups
    group = groups[0]
    assert group["label"] == "OldGame"
    assert len(group["members"]) == 3
    assert {m["role"] for m in group["members"]} == {"program", "cache", "user_data"}


def test_evidence_ids_are_unique_incremental():
    book = EvidenceBook()
    first = book.add("size", "a")
    second = book.add("mtime", "b")
    assert first.id == "E1"
    assert second.id == "E2"
    assert [item["id"] for item in book.to_list()] == ["E1", "E2"]


def test_folder_assessment_mixed_keeps_user_data():
    folder = "D:/Games/OldGame"
    results = [
        _result(f"{folder}/OldGame.exe", "keep", 45_000_000),
        _result(f"{folder}/crash.log", "safe_to_delete", 12_000_000),
        _result(f"{folder}/save.dat", "keep", 45_000),
        _result("C:/Users/alice/Documents/OldGame/screenshot.png", "keep", 5_000_000),
    ]
    assessment = FolderAssessor().assess(folder, results)
    assert assessment.verdict in ("needs_review", "clean_cache_only")
    assert any(item["path"].endswith("save.dat") for item in assessment.keep_items)
    assert any(item["path"].endswith("crash.log") for item in assessment.clean_items)
    assert assessment.evidence
    assert assessment.to_dict()["evidence_ids"]


def test_folder_assessment_all_cache_is_cleanable():
    folder = "C:/Users/alice/AppData/Local/Temp/pack"
    results = [
        _result(f"{folder}/a.tmp", "safe_to_delete", 1000, mtime=1600000000.0),
        _result(f"{folder}/b.log", "safe_to_delete", 2000, mtime=1600000000.0),
    ]
    assessment = FolderAssessor().assess(folder, results)
    assert assessment.verdict in ("clean_all_with_backup", "clean_cache_only")
    assert len(assessment.clean_items) == 2
    assert not assessment.keep_items
