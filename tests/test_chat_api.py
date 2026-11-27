"""智能建议 HTTP API 测试。"""

import json
import threading
import urllib.error
import urllib.request

import pytest

from disk_cleaner.chat_service import ChatService
from disk_cleaner.cleaner.executor import CleanExecutor
from disk_cleaner.gui.app import GUIHandler, ThreadingHTTPServer


def _result(path, decision="safe_to_delete", size=1000, mtime=1600000000.0):
    return {
        "path": path,
        "name": path.rsplit("/", 1)[-1],
        "size": size,
        "size_mb": size / 1024 / 1024,
        "extension": "",
        "mtime": mtime,
        "decision": decision,
        "confidence": 0.9,
        "reason": "测试结果",
        "source": "ai",
    }


@pytest.fixture
def chat_server(tmp_path):
    GUIHandler.token = "chat-token"
    GUIHandler.port = 0
    GUIHandler.scanned_paths = set()
    GUIHandler.last_results = [
        _result("D:/Games/OldGame/OldGame.exe", "keep", 45_000_000),
        _result("D:/Games/OldGame/crash.log", "safe_to_delete", 12_000_000),
        _result("C:/Users/alice/Documents/OldGame/save.dat", "keep", 45_000),
    ]
    GUIHandler.scanned_paths = {r["path"] for r in GUIHandler.last_results}
    GUIHandler.chat_service = ChatService(
        executor_factory=lambda: CleanExecutor(backup_dir=str(tmp_path / "backup"))
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), GUIHandler)
    GUIHandler.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{GUIHandler.port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        GUIHandler.token = ""
        GUIHandler.last_results = []
        GUIHandler.chat_service = None


def _post(url, payload, token="chat-token"):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-DC-Token": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def test_chat_session_message_and_plan(chat_server):
    status, session = _post(chat_server + "/api/chat/session", {
        "scope": "folder",
        "target": "D:/Games/OldGame",
    })
    assert status == 200
    assert session["session"]["scope"] == "folder"
    session_id = session["session"]["session_id"]

    status, answer = _post(chat_server + "/api/chat/message", {
        "session_id": session_id,
        "text": "这个文件夹整体能删吗？",
    })
    assert status == 200
    assert answer["source"] == "local"
    assert "结论" in answer["answer"]

    status, plan = _post(chat_server + "/api/chat/plan", {
        "session_id": session_id,
        "mode": "backup",
    })
    assert status == 200
    assert "plan" in plan
    assert plan["plan"]["mode"] == "backup"


def test_chat_requires_token(chat_server):
    status, _ = _post(
        chat_server + "/api/chat/session",
        {"scope": "scan"},
        token="wrong",
    )
    assert status == 403


def test_chat_without_scan_is_rejected(chat_server):
    GUIHandler.last_results = []
    status, body = _post(chat_server + "/api/chat/session", {"scope": "scan"})
    assert status == 400
    assert "先分析" in body["error"]
