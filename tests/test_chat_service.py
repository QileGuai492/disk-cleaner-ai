"""清理顾问（只读聊天服务）测试。"""

import json

from disk_cleaner.chat_service import ChatService
from disk_cleaner.cleaner.executor import CleanExecutor


def _result(path, decision="needs_review", size=1000, mtime=1600000000.0, reason=""):
    return {
        "path": path,
        "name": path.rsplit("/", 1)[-1],
        "size": size,
        "size_mb": round(size / 1024 / 1024, 1),
        "extension": "",
        "mtime": mtime,
        "decision": decision,
        "confidence": 0.9,
        "reason": reason,
        "source": "ai",
    }


def test_gradle_explain_is_friendly_and_not_cleanup_only():
    target = "C:/Users/alice/.gradle/caches"
    results = [
        _result(f"{target}/modules-2/files-2.1/a.jar", "safe_to_delete", 2_000_000),
        _result(f"{target}/build-cache/a.bin", "safe_to_delete", 1_000_000),
    ]
    service = ChatService()
    context = service.create_session(results, scope="folder", target=target)

    answer = service.answer(context.session_id, "gradle是什么？")
    assert answer["verdict_label"] == "说明"
    assert "Gradle" in answer["answer"]
    assert "构建" in answer["answer"]
    assert "这不是缓存" not in answer["answer"]
    assert all(action["type"] != "draft_plan" for action in answer["actions"])


def test_gradle_build_script_is_explained_as_keep():
    target = "D:/Projects/demo/build.gradle"
    service = ChatService()
    context = service.create_session(
        [_result(target, "keep", 2_000)],
        scope="file",
        target=target,
    )
    answer = service.answer(context.session_id, "这个 build.gradle 是什么？")
    assert "构建脚本" in answer["answer"]
    assert "不要删除" in answer["answer"]


def test_clean_question_starts_with_what_it_is():
    target = "C:/Users/alice/.gradle/caches"
    service = ChatService()
    context = service.create_session(
        [_result(f"{target}/a.jar", "safe_to_delete", 2_000_000)],
        scope="folder",
        target=target,
    )
    answer = service.answer(context.session_id, "这个能删吗？")
    assert "这是什么" in answer["answer"]
    assert "Gradle" in answer["answer"]


def test_ai_can_explain_concept_without_evidence():
    target = "C:/Users/alice/.gradle/caches"
    captured = {}

    class FakeAI:
        def analyze(self, prompt):
            captured["prompt"] = prompt
            return json.dumps({
                "verdict": "needs_review",
                "summary": "通用说明：Gradle 是 Java/Kotlin/Android 的构建工具。",
                "evidence_ids": [],
                "risks": [],
                "confidence": 0.7,
            })

    service = ChatService(ai_factory=lambda provider: FakeAI())
    context = service.create_session(
        [_result(f"{target}/a.jar", "safe_to_delete", 2_000_000)],
        scope="folder",
        target=target,
    )
    answer = service.answer(context.session_id, "gradle是什么？", provider="deepseek")
    assert answer["source"] == "ai"
    assert answer["verdict_label"] == "说明"
    assert all(action["type"] != "draft_plan" for action in answer["actions"])
    assert "explain" in captured["prompt"]


def test_file_session_local_answer():
    target = "C:/Users/alice/AppData/Local/Temp/a.tmp"
    service = ChatService()
    context = service.create_session(
        [_result(target, "safe_to_delete", reason="临时文件")],
        scope="file",
        target=target,
    )
    assert context.summary_for_ui()["scope"] == "file"
    answer = service.answer(context.session_id, "这个文件能删吗？")
    assert answer["source"] == "local"
    assert "结论" in answer["answer"]
    assert answer["evidence_ids"]


def test_folder_session_keeps_user_data(tmp_path):
    folder = "D:/Games/OldGame"
    results = [
        _result(f"{folder}/OldGame.exe", "keep", 45_000_000),
        _result(f"{folder}/crash.log", "safe_to_delete", 12_000_000),
        _result(f"{folder}/save.dat", "keep", 45_000),
        _result("C:/Users/alice/Documents/OldGame/screenshot.png", "keep", 5_000_000),
    ]
    service = ChatService(
        executor_factory=lambda: CleanExecutor(backup_dir=str(tmp_path / "backup"))
    )
    context = service.create_session(results, scope="folder", target=folder)
    assert context.verdict in ("needs_review", "clean_cache_only")

    answer = service.answer(context.session_id, "这个文件夹整体能删吗？")
    assert "建议保留" in answer["answer"] or "可清理" in answer["answer"]
    assert any(action["type"] == "draft_plan" for action in answer["actions"])

    plan = service.draft_plan(context.session_id)
    assert "plan" in plan
    assert plan["plan"]["mode"] == "backup"
    # 只生成计划，不产生备份批次
    assert not (tmp_path / "backup").exists() or not any(
        (tmp_path / "backup").iterdir()
    )


def test_ai_answer_anonymizes_paths_and_validates_evidence():
    target = "C:/Users/alice/AppData/Local/Temp/a.tmp"
    captured = {}

    class FakeAI:
        def analyze(self, prompt):
            captured["prompt"] = prompt
            return json.dumps({
                "verdict": "likely_safe",
                "summary": "临时文件，建议备份后清理。",
                "evidence_ids": ["E1"],
                "risks": ["可能被占用"],
                "actions": [
                    {"type": "draft_plan", "label": "生成清理计划"},
                    {"type": "delete_now", "label": "直接删除"},
                ],
                "confidence": 0.8,
            })

    service = ChatService(ai_factory=lambda provider: FakeAI())
    context = service.create_session(
        [_result(target, "safe_to_delete", reason="临时文件")],
        scope="file",
        target=target,
    )
    answer = service.answer(context.session_id, "删了会怎样？", provider="deepseek")
    assert answer["source"] == "ai"
    assert "alice" not in captured["prompt"]
    assert "<USER>" in captured["prompt"]
    assert all(action["type"] != "delete_now" for action in answer["actions"])


def test_invalid_ai_response_falls_back_to_local():
    target = "C:/Temp/a.tmp"

    class BadAI:
        def analyze(self, prompt):
            return "not json"

    service = ChatService(ai_factory=lambda provider: BadAI())
    context = service.create_session(
        [_result(target, "safe_to_delete", reason="临时文件")],
        scope="file",
        target=target,
    )
    answer = service.answer(context.session_id, "能删吗？", provider="deepseek")
    assert answer["source"] == "local"


def test_what_if_answer_mentions_backup():
    target = "C:/Temp/a.tmp"
    service = ChatService()
    context = service.create_session(
        [_result(target, "safe_to_delete", reason="临时文件")],
        scope="file",
        target=target,
    )
    answer = service.answer(context.session_id, "如果删了会怎样？")
    assert "如果删除" in answer["answer"]
    assert "备份" in answer["answer"]


def test_session_keeps_short_history():
    target = "C:/Temp/a.tmp"
    service = ChatService()
    context = service.create_session(
        [_result(target, "safe_to_delete", reason="临时文件")],
        scope="file",
        target=target,
    )
    service.answer(context.session_id, "这是什么？")
    service.answer(context.session_id, "删了会怎样？")
    assert len(context.history) == 4
    assert context.history[0]["role"] == "user"


def test_unknown_session():
    assert "error" in ChatService().answer("missing", "hello")
