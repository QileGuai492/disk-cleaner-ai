"""轻量 Web GUI——内置 HTTP 服务 + 单页应用"""

import html as html_module
import json
import os
import secrets
import subprocess
import sys
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

from disk_cleaner.analyzer.engine import AnalysisEngine
from disk_cleaner.cleaner.executor import CleanExecutor
from disk_cleaner.db.models import Database


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True  # Ctrl+C 时自动杀掉所有请求线程


def _get_db():
    base = os.path.expanduser("~/.disk-cleaner")
    os.makedirs(base, exist_ok=True)
    db = Database(os.path.join(base, "cache.db"))
    db.initialize()
    return db


def _model_for(provider: str) -> str:
    defaults = {
        "deepseek": "deepseek-v4-flash",
        "openai": "gpt-4o-mini",
        "claude": "claude-3-haiku-20240307",
        "gemini": "gemini-1.5-flash",
        "ollama": "qwen2.5:1.5b",
    }
    try:
        from disk_cleaner.config import load_config
        config = load_config()
        if config.ai.provider == provider and config.ai.model:
            return config.ai.model
    except Exception:
        pass
    return defaults.get(provider, "")


def _load_gui_html() -> str:
    """从 static/index.html 加载页面，避免 HTML/JS/CSS 与 Python 混在一起。"""
    path = Path(__file__).resolve().parent / "static" / "index.html"
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"<h1>GUI 静态资源缺失</h1><p>{html_module.escape(str(exc))}</p>"


GUI_HTML = _load_gui_html()



class GUIHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器"""

    engine: AnalysisEngine | None = None
    last_results: list[dict] = []
    token: str = ""
    port: int = 8765
    scanned_paths: set[str] = set()

    # ---- 安全校验 -------------------------------------------------
    def _check_host(self) -> bool:
        """只接受本机 Host，防止 DNS rebinding。"""
        host = (self.headers.get("Host") or "").lower()
        if not host:
            return True  # 非浏览器客户端（测试/curl）可能不带 Host
        allowed = {
            f"127.0.0.1:{GUIHandler.port}",
            f"localhost:{GUIHandler.port}",
        }
        return host in allowed

    def _check_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        allowed = {
            f"http://127.0.0.1:{GUIHandler.port}",
            f"http://localhost:{GUIHandler.port}",
        }
        return origin in allowed

    def _token_from_request(self) -> str:
        token = self.headers.get("X-DC-Token", "")
        if token:
            return token
        qs = parse_qs(urlparse(self.path).query)
        return (qs.get("token") or [""])[0]

    def _authorized(self) -> bool:
        if not self._check_host() or not self._check_origin():
            return False
        token = self._token_from_request()
        return bool(GUIHandler.token) and secrets.compare_digest(token, GUIHandler.token)

    def _forbid(self, message: str = "forbidden"):
        self._respond_json({"error": message}, status=403)

    def _discard_body(self) -> None:
        """拒绝请求时丢弃已发送的请求体，避免连接被客户端重置。"""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return
        if 0 < length <= 1_000_000:
            try:
                self.rfile.read(length)
            except Exception:
                pass

    # ---- HTTP 入口 -------------------------------------------------
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            if not self._check_host():
                self._forbid("仅允许本机访问")
                return
            self._respond_html(GUI_HTML)
        elif self.path.startswith("/api/analyze-stream"):
            if not self._authorized():
                self._forbid("未授权：请刷新页面后重试")
                return
            # EventSource GET 请求——从 query string 解析参数
            qs = parse_qs(urlparse(self.path).query)
            data = {k: v[0] for k, v in qs.items()}
            # 类型转换
            if "top" in data:
                try:
                    data["top"] = int(data["top"])
                except ValueError:
                    data["top"] = 100
            if "recursive" in data:
                data["recursive"] = data["recursive"].lower() != "false"
            if "use_ai" in data:
                data["use_ai"] = data["use_ai"].lower() == "true"
            if "force" in data:
                data["force"] = data["force"].lower() == "true"
            self._handle_analyze_stream(data)
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        # 不提供 CORS：本工具只允许同源页面访问
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        if not self._authorized():
            self._discard_body()
            self._forbid("未授权：请刷新页面后重试")
            return

        try:
            content_len = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._respond_json({"error": "Content-Length 无效"}, status=400)
            return
        if content_len > 1_000_000:
            self._respond_json({"error": "请求体过大"}, status=413)
            return

        body = self.rfile.read(content_len)
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._respond_json({"error": "Content-Type 必须是 application/json"}, status=415)
            return

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._respond_json({"error": "JSON 格式错误"}, status=400)
            return

        if self.path == "/api/check-ai":
            self._handle_check_ai()
        elif self.path == "/api/scan":
            self._handle_scan(data)
        elif self.path == "/api/analyze":
            self._handle_analyze(data)
        elif self.path == "/api/analyze-stream":
            self._handle_analyze_stream(data)
        elif self.path == "/api/clean":
            self._handle_clean(data)
        elif self.path == "/api/open-file":
            self._handle_open_file(data)
        elif self.path == "/api/cancel":
            self._handle_cancel()
        elif self.path == "/api/report":
            self._handle_report()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_check_ai(self):
        from disk_cleaner.db.keystore import KeyStore
        store = KeyStore()
        providers = list(store.list_providers())

        # 环境变量也算已配置
        env_map = {
            "deepseek": "DEEPSEEK_API_KEY",
            "openai": "OPENAI_API_KEY",
            "claude": "ANTHROPIC_API_KEY",
            "gemini": "GEMINI_API_KEY",
        }
        for name, env in env_map.items():
            if os.environ.get(env) and name not in providers:
                providers.append(name)

        # Ollama 不需要 Key，探测服务是否在运行
        if "ollama" not in providers:
            try:
                import urllib.request
                with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=0.8) as resp:
                    if resp.status == 200:
                        providers.append("ollama")
            except Exception:
                pass

        self._respond_json({"configured": len(providers) > 0, "providers": providers})

    def _handle_scan(self, data: dict):
        path = data.get("path", ".")
        top = data.get("top", 100)
        if not os.path.exists(path):
            self._respond_json({"error": f"路径不存在: {path}"})
            return
        self._respond_json({"path": path, "top": top, "status": "ok"})

    def _handle_analyze(self, data: dict):
        path = data.get("path", ".")
        top = data.get("top", 100)
        recursive = data.get("recursive", True)
        use_ai = data.get("use_ai", False)
        provider = data.get("provider", "deepseek")
        force = data.get("force", False)

        if not os.path.exists(path):
            self._respond_json({"error": f"路径不存在: {path}"})
            return

        db = _get_db()
        try:
            ai_provider = provider if use_ai else "local"
            eng = AnalysisEngine(db, ai_provider=ai_provider, ai_model=_model_for(provider))
            GUIHandler.engine = eng
            results = eng.analyze_path(path, top_n=top, recursive=recursive, force=force)
            stats = eng.stats
            GUIHandler.last_results = results
            GUIHandler.scanned_paths = {os.path.abspath(r["path"]) for r in results}
            try:
                from disk_cleaner.db.models import ScanRecord
                records = ScanRecord(db)
                scan_id = records.start_scan(os.path.abspath(path), len(results))
                records.finish_scan(scan_id, len(results), 0, 0)
            except Exception:
                pass
            safe = len([r for r in results if r["decision"] == "safe_to_delete"])
            likely = len([r for r in results if r["decision"] == "likely_safe"])
            review = len([r for r in results if r["decision"] == "needs_review"])
            keep = len([r for r in results if r["decision"] in ("keep", "critical")])
            self._respond_json({
                "results": results, "stats": stats,
                "summary": {"safe": safe, "likely": likely, "review": review, "keep": keep},
            })
        except PermissionError:
            self._respond_json({"error": f"没有权限访问此目录，请以管理员身份运行或选择其他目录"})
        except Exception as e:
            self._respond_json({"error": f"分析出错: {e}"})
        finally:
            db.close()

    def _handle_analyze_stream(self, data: dict):
        """SSE 流式分析——逐文件推送进度"""
        path = data.get("path", ".")
        top = data.get("top", 100)
        recursive = data.get("recursive", True)
        use_ai = data.get("use_ai", False)
        provider = data.get("provider", "deepseek")
        force = data.get("force", False)

        if not os.path.exists(path):
            self._respond_json({"error": f"路径不存在: {path}"}, status=400)
            return

        # 每次新扫描重置本次可清理白名单
        GUIHandler.scanned_paths = set()

        # SSE 响应头
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        db = _get_db()
        results_buf: list[dict] = []
        try:
            ai_provider = provider if use_ai else "local"
            eng = AnalysisEngine(db, ai_provider=ai_provider, ai_model=_model_for(provider))
            GUIHandler.engine = eng

            for evt in eng.analyze_directory_stream(path, top_n=top, recursive=recursive, force=force):
                if evt["type"] == "cancelled":
                    self._sse_send({"type": "cancelled", "current": evt["current"], "total": evt["total"]})
                    break
                result = evt["result"]
                results_buf.append(result)
                GUIHandler.scanned_paths.add(os.path.abspath(result["path"]))
                self._sse_send({"type": "progress", "current": evt["current"], "total": evt["total"], "result": result})

            GUIHandler.last_results = results_buf
            try:
                from disk_cleaner.db.models import ScanRecord
                records = ScanRecord(db)
                scan_id = records.start_scan(os.path.abspath(path), eng.stats.get("total", len(results_buf)))
                records.finish_scan(scan_id, len(results_buf), 0, 0)
            except Exception:
                pass
            stats = eng.stats
            safe = len([r for r in results_buf if r["decision"] == "safe_to_delete"])
            likely = len([r for r in results_buf if r["decision"] == "likely_safe"])
            review = len([r for r in results_buf if r["decision"] == "needs_review"])
            keep = len([r for r in results_buf if r["decision"] in ("keep", "critical")])
            self._sse_send({"type": "done", "stats": stats, "summary": {"safe": safe, "likely": likely, "review": review, "keep": keep}})
        except Exception as e:
            self._sse_send({"type": "error", "message": str(e)})
        finally:
            db.close()

    def _sse_send(self, data: dict):
        """发送 SSE 事件"""
        self.wfile.write(f"data: {json.dumps(data, ensure_ascii=False)}\n\n".encode())
        self.wfile.flush()

    def _handle_open_file(self, data: dict):
        """在文件资源管理器中打开并选中文件"""
        path = data.get("path", "")
        if not path or not os.path.exists(path):
            self._respond_json({"error": "文件不存在"}, status=404)
            return
        if os.path.abspath(path) not in GUIHandler.scanned_paths:
            self._respond_json({"error": "只能打开本次扫描结果中的文件"}, status=403)
            return
        try:
            subprocess.run(
                ["explorer", "/select,", os.path.abspath(path)],
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            self._respond_json({"status": "ok"})
        except Exception as e:
            self._respond_json({"error": str(e)}, status=500)

    def _handle_cancel(self):
        if GUIHandler.engine:
            GUIHandler.engine.cancel()
        self._respond_json({"status": "cancelled"})

    def _handle_clean(self, data: dict):
        files = data.get("files", [])
        if not isinstance(files, list) or not files:
            self._respond_json({"error": "未选择文件"}, status=400)
            return
        if len(files) > 1000:
            self._respond_json({"error": "单次最多清理 1000 个文件"}, status=400)
            return

        requested = [os.path.abspath(str(f)) for f in files]
        blocked = [p for p in requested if p not in GUIHandler.scanned_paths]
        if blocked:
            self._respond_json({
                "error": f"拒绝清理：{len(blocked)} 个路径不在本次扫描结果中，请重新分析后再试"
            }, status=403)
            return

        executor = CleanExecutor()
        plan = executor.plan(requested, mode="backup")
        if not plan.allowed:
            reasons = "；".join(f"{r['path']}: {r['reason']}" for r in plan.rejected[:5])
            self._respond_json({"error": f"安全策略拒绝：{reasons}"}, status=403)
            return

        res = executor.execute(plan)
        summary = executor.get_summary(res)
        try:
            from disk_cleaner.db.models import ScanRecord
            stat_db = _get_db()
            try:
                ScanRecord(stat_db).record_cleanup(
                    summary["success_count"],
                    summary.get("total_moved", 0),
                    summary.get("total_freed_real", 0),
                )
            finally:
                stat_db.close()
        except Exception:
            pass
        self._respond_json({
            "moved": summary.get("total_moved", 0),
            "freed": summary.get("total_freed_real", 0),
            "skipped": summary.get("failed_count", 0),
            "batch_id": executor.last_batch_id,
            "warning": "；".join(plan.warnings),
        })

    def _handle_report(self):
        safe = [r for r in GUIHandler.last_results if r["decision"] in ("safe_to_delete", "likely_safe")]
        reclaim = sum(r["size"] for r in safe)
        reclaim_str = f"{reclaim / (1024**3):.2f} GB" if reclaim > 1e9 else f"{reclaim / (1024**2):.1f} MB"
        rows = "".join(
            f"<tr><td>{html_module.escape(str(r['name']))}</td>"
            f"<td>{r['size_mb']:.1f} MB</td>"
            f"<td>{html_module.escape(str(r['decision']))}</td>"
            f"<td>{html_module.escape(str(r.get('reason', '')))}</td></tr>"
            for r in safe[:50]
        )
        html = f"<html><head><meta charset=utf-8><title>清理报告</title></head><body><h1>清理报告</h1><p>可释放: {reclaim_str}</p><table border=1>{rows}</table></body></html>"
        self._respond_json({"html": html})

    def _respond_json(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if status >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode())

    def _respond_html(self, html: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        # 会话 Token 只注入本机页面，请求 API 时必须回传
        self.wfile.write(html.replace("__DC_TOKEN__", GUIHandler.token).encode())

    def log_message(self, format, *args):
        pass  # 静默日志


def start_gui(port: int | None = None, open_browser: bool | None = None):
    """启动 Web GUI"""
    try:
        from disk_cleaner.logging_utils import setup_logging
        setup_logging()
    except Exception:
        pass
    if port is None or open_browser is None:
        try:
            from disk_cleaner.config import load_config
            config = load_config()
            if port is None:
                port = config.gui.port
            if open_browser is None:
                open_browser = config.gui.open_browser
        except Exception:
            pass
    port = 8765 if port is None else port
    open_browser = True if open_browser is None else open_browser

    GUIHandler.token = secrets.token_urlsafe(32)
    GUIHandler.port = port
    GUIHandler.scanned_paths = set()

    server = ThreadingHTTPServer(("127.0.0.1", port), GUIHandler)
    server.daemon_threads = True
    url = f"http://127.0.0.1:{port}"
    print(f"GUI 已启动: {url}")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nGUI 已停止")
        server.shutdown()
