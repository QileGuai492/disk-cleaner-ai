"""GUI 安全边界测试：Token、Origin、Content-Type、路径白名单。"""

import json
import threading
import urllib.error
import urllib.request

import pytest

from disk_cleaner.gui.app import GUIHandler, ThreadingHTTPServer


@pytest.fixture
def gui_server():
    GUIHandler.token = "test-token"
    GUIHandler.port = 0
    GUIHandler.scanned_paths = set()
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
        GUIHandler.scanned_paths = set()


def _post(url, payload, token=None, content_type="application/json", origin=None, host=None):
    headers = {"Content-Type": content_type}
    if token:
        headers["X-DC-Token"] = token
    if origin:
        headers["Origin"] = origin
    if host:
        headers["Host"] = host
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


def test_page_contains_session_token(gui_server):
    with urllib.request.urlopen(gui_server + "/", timeout=5) as response:
        body = response.read().decode("utf-8")
    assert "/static/app.js" in body
    assert "chatPanel" in body
    assert "智能建议" in body

    with urllib.request.urlopen(gui_server + "/static/app.js", timeout=5) as response:
        script = response.read().decode("utf-8")
    assert "test-token" in script
    assert "__DC_TOKEN__" not in script


def test_clean_without_token_is_rejected(gui_server):
    status, _ = _post(gui_server + "/api/clean", {"files": ["C:\\Windows\\System32\\kernel32.dll"]})
    assert status == 403


def test_clean_with_foreign_origin_is_rejected(gui_server):
    status, _ = _post(
        gui_server + "/api/clean",
        {"files": []},
        token="test-token",
        origin="http://evil.example",
    )
    assert status == 403


def test_clean_with_foreign_host_is_rejected(gui_server):
    status, _ = _post(
        gui_server + "/api/clean",
        {"files": []},
        token="test-token",
        host="evil.example",
    )
    assert status == 403


def test_clean_rejects_non_json_content_type(gui_server):
    status, _ = _post(
        gui_server + "/api/clean",
        {"files": []},
        token="test-token",
        content_type="text/plain",
    )
    assert status == 415


def test_clean_rejects_path_outside_scan(gui_server):
    status, body = _post(
        gui_server + "/api/clean",
        {"files": ["C:\\Windows\\System32\\kernel32.dll"]},
        token="test-token",
    )
    assert status == 403
    assert "不在本次扫描结果" in body


def test_open_file_rejects_path_outside_scan(gui_server):
    status, body = _post(
        gui_server + "/api/open-file",
        {"path": "C:\\Windows\\System32\\kernel32.dll"},
        token="test-token",
    )
    assert status == 403
    assert "扫描结果" in body
