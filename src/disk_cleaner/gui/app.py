"""轻量 Web GUI——内置 HTTP 服务 + 单页应用"""

import json
import os
import sys
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True  # Ctrl+C 时自动杀掉所有请求线程
from pathlib import Path

from disk_cleaner.analyzer.engine import AnalysisEngine
from disk_cleaner.cleaner.executor import CleanExecutor
from disk_cleaner.db.models import Database


def _get_db():
    base = os.path.expanduser("~/.disk-cleaner")
    os.makedirs(base, exist_ok=True)
    db = Database(os.path.join(base, "cache.db"))
    db.initialize()
    return db


GUI_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<title>AI 磁盘清理工具</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,Segoe UI,sans-serif;background:#0d1117;color:#c9d1d9;max-width:960px;margin:0 auto;padding:20px}
h1{color:#58a6ff;font-size:24px;margin-bottom:8px}
.sub{color:#8b949e;font-size:14px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}
.card h2{font-size:16px;color:#f0f6fc;margin-bottom:12px}
input,select,button{padding:5px 10px;border:1px solid #30363d;border-radius:6px;background:#0d1117;color:#c9d1d9;font-size:14px}
input#path{width:380px;max-width:60vw}
button{background:#238636;color:#fff;cursor:pointer;border-color:#238636}
button:hover:not(:disabled){background:#2ea043}
button:disabled{opacity:.5;cursor:not-allowed}
button.cancel{background:#da3633;border-color:#da3633}
button.cancel:hover:not(:disabled){background:#f85149}
select{width:60px} select#provider{width:110px}
label.chk{font-size:13px;color:#c9d1d9;cursor:pointer;margin:0 6px}
label.chk input{width:auto;margin:0 3px 0 0;vertical-align:middle;padding:0}
table{width:100%;table-layout:fixed;border-collapse:collapse;margin-top:12px}
th,td{padding:6px 8px;text-align:left;border-bottom:1px solid #30363d;font-size:13px;white-space:nowrap}
th{color:#8b949e;font-weight:600}
th:nth-child(1),td:nth-child(1){width:30px;text-align:center;padding:6px 2px}
th:nth-child(2),td:nth-child(2){width:33%}
th:nth-child(3),td:nth-child(3){width:12%}
th:nth-child(4),td:nth-child(4){width:12%}
th:nth-child(5),td:nth-child(5){width:11%}
th:nth-child(6),td:nth-child(6){width:32%}
.cell-scroll{overflow-x:auto;white-space:nowrap;max-width:100%}
.cell-scroll::-webkit-scrollbar{height:6px}
.cell-scroll::-webkit-scrollbar-thumb{background:#8b949e;border-radius:3px}
.safe{color:#7ee787}.likely{color:#d2a8ff}.review{color:#d29922}.keep{color:#f85149}
.progress{height:4px;background:#30363d;border-radius:2px;margin:10px 0}
.progress-bar{height:100%;background:#238636;border-radius:2px;transition:width .3s}
.progress-bar.cancelled{background:#da3633}
#status{color:#8b949e;font-size:13px;margin-top:8px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:16px}
.stat{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;text-align:center}
.stat .num{font-size:24px;font-weight:700}
.stat .label{font-size:11px;color:#8b949e;margin-top:4px}
.empty{text-align:center;color:#484f58;padding:40px 0;font-size:14px}
</style></head>
<body>
<h1>AI 磁盘清理工具</h1>
<div class="sub">扫描 → AI 分析 → 安全清理</div>

<div class="card">
  <h2>扫描磁盘</h2>
  <div style="margin-bottom:10px">
    <input id="path" placeholder="输入目录路径">
    <select id="top"><option value="50">50</option><option value="100">100</option><option value="200">200</option></select>
    <label class="chk"><input type="checkbox" id="recursive">子目录</label>
    <button id="scanBtn" onclick="handleScan()">开始分析</button>
    <label class="chk" id="aiLabel" title="需先配置 API Key"><input type="checkbox" id="useAI" onchange="toggleAI()" disabled>AI</label>
    <select id="provider" disabled><option value="deepseek">DeepSeek</option><option value="openai">OpenAI</option><option value="ollama">Ollama</option></select>
  </div>
  <div id="progressContainer" style="display:none">
    <div class="progress"><div class="progress-bar" id="progressBar" style="width:0%"></div></div>
    <div id="status"></div>
  </div>
</div>

<div class="card" id="resultsCard">
  <h2>分析结果</h2>
  <div class="summary" id="summary"></div>
  <div id="resultsBody">
    <div class="empty">输入路径点击"开始分析"</div>
  </div>
</div>

<script>
let _busy = false, _ctrl = null;
const $=id=>document.getElementById(id);

async function api(path, data) {
  try {const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data),signal:_ctrl?.signal});return r.json()}
  catch(e){return {error:e.message}}
}
function toggleAI() {
  $('provider').disabled = !$('useAI').checked;
}
function fmtSize(b) {if(b>1e9)return (b/1e9).toFixed(2)+' GB';return (b/1e6).toFixed(1)+' MB'}
const DECO={'safe_to_delete':'safe','likely_safe':'likely','needs_review':'review','keep':'keep','critical':'keep'}
const LBL={safe_to_delete:'可删除',likely_safe:'概率可删',needs_review:'需确认',keep:'保留',critical:'禁止删除'}
const SRC={cache:'缓存',rule:'规则',ai:'AI',local:'本地分析',dependency:'依赖分析',fingerprint:'指纹库',cancelled:'已取消',error:'异常',ai_cluster:'AI聚类',ai_cross_cluster:'AI交叉聚类'}

// 页面持久化
function saveState() {
  localStorage.setItem('dc_path',$('path').value);
  localStorage.setItem('dc_top',$('top').value);
  localStorage.setItem('dc_recursive',$('recursive').checked);
  localStorage.setItem('dc_useAI',$('useAI').checked);
  localStorage.setItem('dc_provider',$('provider').value);
}
function loadState() {
  $('path').value = localStorage.getItem('dc_path')||'';
  $('top').value = localStorage.getItem('dc_top')||'50';
  $('recursive').checked = localStorage.getItem('dc_recursive')==='true';
  $('useAI').checked = localStorage.getItem('dc_useAI')==='true';
  $('provider').value = localStorage.getItem('dc_provider')||'deepseek';
  toggleAI();
  const saved = localStorage.getItem('dc_results');
  if (saved) {
    try { showResults(JSON.parse(saved)); } catch(e) {}
  }
}

// 检测 AI 是否已配置
async function checkAIConfig() {
  const r = await api('/api/check-ai', {});
  if (r.configured) {
    $('useAI').disabled = false;
    $('aiLabel').title = '启用云端AI可获得更准确的分析结果';
  }
}

function cleanPath(p) {
  // 去掉 Win11 复制路径时带的引号
  return p.trim().replace(/^[\x22\x27“”‘’]+|[\x22\x27“”‘’]+$/g, '');
}

async function handleScan() {
  console.log('handleScan called, _busy='+_busy);
  const btn = $('scanBtn');
  if (_busy) {
    // 正在扫描中，点按钮 = 取消
    if (_ctrl) _ctrl.abort();
    _ctrl = null;
    _busy = false;
    $('progressBar').style.width = '0%';
    $('progressBar').classList.add('cancelled');
    $('status').textContent = '已取消';
    btn.textContent = '开始分析';
    btn.className = '';
    return;
  }
  _ctrl = new AbortController();
  _busy = true;
  try { saveState(); } catch(e) { console.log('saveState error:', e); }
  btn.textContent = '取消';
  btn.className = 'cancel';
  btn.disabled = false;

  $('progressContainer').style.display = 'block';
  $('progressBar').style.width = '20%';
  $('progressBar').classList.remove('cancelled');
  $('status').textContent = '正在扫描...';
  $('resultsBody').innerHTML = '<div class="empty">分析中...</div>';

  try {
    const scanParams = {path:cleanPath($('path').value),top:parseInt($('top').value),recursive:$('recursive').checked,
      use_ai:$('useAI').checked, provider:$('provider').value, force:$('useAI').checked};
    await api('/api/scan', scanParams);
    if (!_busy) { cancelled(); return; }
    $('progressBar').style.width = '60%';
    $('status').textContent = $('useAI').checked ? '正在 AI 分析...' : '正在本地分析...';
    const results = await api('/api/analyze', scanParams);
    if (!_busy) { cancelled(); return; }
    $('progressBar').style.width = '100%';
    $('status').textContent = '完成';
    showResults(results);
  } catch(e) {
    console.log('handleScan error:', e);
    $('status').textContent = '错误: ' + e.message;
  } finally {
    _ctrl = null;
    _busy = false;
    btn.textContent = '开始分析';
    btn.className = '';
    btn.disabled = false;
  }
}

function cancelled() {
  $('progressBar').classList.add('cancelled');
  $('status').textContent = '已取消';
}

function showResults(data) {
  const results = data.results || [], stats = data.stats || {}, summary = data.summary || {};
  $('summary').innerHTML =
    `<div class="stat"><div class="num safe">${summary.safe||0}</div><div class="label">可清理</div></div>
     <div class="stat"><div class="num likely">${summary.likely||0}</div><div class="label">可能可清理</div></div>
     <div class="stat"><div class="num review">${summary.review||0}</div><div class="label">需确认</div></div>
     <div class="stat"><div class="num keep">${summary.keep||0}</div><div class="label">建议保留</div></div>
     <div class="stat"><div class="num">${stats.cache_hits||0}</div><div class="label">缓存命中</div></div>
     <div class="stat"><div class="num">${stats.ai_calls||0}</div><div class="label">AI 调用</div></div>`;

  if (!results.length) {
    $('resultsBody').innerHTML = '<div class="empty">未发现可分析的文件</div>';
    localStorage.removeItem('dc_results');
    return;
  }
  localStorage.setItem('dc_results', JSON.stringify(data));

  const showDir = $('recursive').checked;
  $('resultsBody').innerHTML =
    `<div style="margin:8px 0">
       <button onclick="cleanSelected()">清理选中</button>
       <button onclick="getReport()" style="margin-left:6px">导出报告</button>
     </div>
     <div style="overflow-x:auto"><table id="resultsTable">
       <thead><tr><th></th><th>文件</th><th>大小</th><th>判定</th><th>来源</th><th>理由</th></tr></thead>
       <tbody>${results.map(r=>`<tr>
         <td><input type="checkbox" value="${escAttr(r.path)}" ${r.decision==='safe_to_delete'?'checked':''}></td>
         <td><div class="cell-scroll">${escHtml(showDir?r.path.replace(/\\\\/g,'/').replace(cleanPath($('path').value).replace(/\\\\/g,'/').replace(/\\/$/,'')+'/',''):r.name)}</div></td>
         <td>${fmtSize(r.size)}</td>
         <td class="${DECO[r.decision]||''}">${LBL[r.decision]||r.decision}</td>
         <td>${SRC[r.source]||r.source||''}</td>
         <td><div class="cell-scroll">${escHtml(r.reason||'')}</div></td>
       </tr>`).join('')}</tbody></table></div>`;
}

function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function escAttr(s){return String(s).replace(/"/g,'&quot;')}

async function cleanSelected() {
  const cbs = document.querySelectorAll('#resultsTable input:checked');
  const files = [...cbs].map(c=>c.value);
  if (!files.length) return alert('请先勾选文件');
  if (!confirm('确认清理 ' + files.length + ' 个文件？')) return;
  const r = await api('/api/clean', {files});
  alert('已清理 ' + r.success + ' 个，释放 ' + fmtSize(r.freed));
}

async function getReport() {
  const r = await api('/api/report', {});
  const w = window.open('', '_blank');
  w.document.write(r.html);
  w.document.close();
}
loadState();
checkAIConfig();
// 输入变化自动保存
['path','top','recursive','useAI','provider'].forEach(id=>{
  $(id).addEventListener('change',saveState);
  $(id).addEventListener('input',saveState);
});
</script></body></html>"""


class GUIHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器"""

    engine: AnalysisEngine | None = None
    last_results: list[dict] = []

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._respond_html(GUI_HTML)
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}

        if self.path == "/api/check-ai":
            self._handle_check_ai()
        elif self.path == "/api/scan":
            self._handle_scan(data)
        elif self.path == "/api/analyze":
            self._handle_analyze(data)
        elif self.path == "/api/clean":
            self._handle_clean(data)
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
        providers = store.list_providers()
        has_env = bool(os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY"))
        self._respond_json({"configured": len(providers) > 0 or has_env, "providers": providers})

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
            eng = AnalysisEngine(db, ai_provider=ai_provider)
            GUIHandler.engine = eng
            results = eng.analyze_path(path, top_n=top, recursive=recursive, force=force)
            stats = eng.stats
            GUIHandler.last_results = results
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

    def _handle_cancel(self):
        if GUIHandler.engine:
            GUIHandler.engine.cancel()
        self._respond_json({"status": "cancelled"})

    def _handle_clean(self, data: dict):
        files = data.get("files", [])
        executor = CleanExecutor()
        res = executor.clean(files, mode="backup")
        summary = executor.get_summary(res)
        self._respond_json({"success": summary["success_count"], "freed": summary["total_freed"]})

    def _handle_report(self):
        safe = [r for r in GUIHandler.last_results if r["decision"] in ("safe_to_delete", "likely_safe")]
        reclaim = sum(r["size"] for r in safe)
        reclaim_str = f"{reclaim / (1024**3):.2f} GB" if reclaim > 1e9 else f"{reclaim / (1024**2):.1f} MB"
        rows = "".join(f"<tr><td>{r['name']}</td><td>{r['size_mb']:.1f} MB</td><td>{r['decision']}</td></tr>" for r in safe[:50])
        html = f"<html><head><meta charset=utf-8><title>清理报告</title></head><body><h1>清理报告</h1><p>可释放: {reclaim_str}</p><table border=1>{rows}</table></body></html>"
        self._respond_json({"html": html})

    def _respond_json(self, data: dict):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode())

    def _respond_html(self, html: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        pass  # 静默日志


def start_gui(port: int = 8765, open_browser: bool = True):
    """启动 Web GUI"""
    # 清理上次崩溃残留的 WAL 锁文件（不影响历史数据）
    db_base = os.path.expanduser("~/.disk-cleaner/cache.db")
    for ext in ("-wal", "-shm"):
        try:
            os.remove(db_base + ext)
        except OSError:
            pass

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
