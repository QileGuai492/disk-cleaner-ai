"""轻量 Web GUI——内置 HTTP 服务 + 单页应用"""

import json
import os
import subprocess
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
:root{
  --bg:#0d1117;--bg-card:#161b22;--bg-input:#0d1117;--border:#30363d;
  --text:#c9d1d9;--text-secondary:#8b949e;--text-heading:#f0f6fc;
  --accent:#58a6ff;--accent-hover:#79c0ff;
  --btn-bg:#238636;--btn-hover:#2ea043;--btn-text:#fff;
  --btn-danger:#da3633;--btn-danger-hover:#f85149;
  --safe:#7ee787;--likely:#d2a8ff;--review:#d29922;--keep:#f85149;
  --progress-bg:#30363d;--empty:#484f58;
}
body.theme-gold{
  --bg:#1a1410;--bg-card:#2d2218;--bg-input:#1e1812;--border:#5a4028;
  --text:#e8d5b5;--text-secondary:#a89070;--text-heading:#f0d9a0;
  --accent:#d4a853;--accent-hover:#e0b860;
  --btn-bg:#b8860b;--btn-hover:#d4a017;--btn-text:#1a1410;
  --btn-danger:#b04530;--btn-danger-hover:#d45a40;
  --safe:#8cb860;--likely:#c8a8e8;--review:#d4a017;--keep:#d4745c;
  --progress-bg:#4a3020;--empty:#5a4030;
}
body.theme-forest{
  --bg:#0d1a12;--bg-card:#15261b;--bg-input:#0d1a12;--border:#2d4a32;
  --text:#c5d8c0;--text-secondary:#7a9e78;--text-heading:#d8f0d0;
  --accent:#4aaf6e;--accent-hover:#5ec97e;
  --btn-bg:#3a8a52;--btn-hover:#4aaf6e;--btn-text:#fff;
  --btn-danger:#a04040;--btn-danger-hover:#c05050;
  --safe:#6ec878;--likely:#b0d0a0;--review:#c8b840;--keep:#d4745c;
  --progress-bg:#2d4a32;--empty:#3a5040;
}
body.theme-ocean{
  --bg:#0d1a2d;--bg-card:#152640;--bg-input:#0d1a2d;--border:#2a4060;
  --text:#c0d0e0;--text-secondary:#6888a8;--text-heading:#d0e0f8;
  --accent:#4a90d9;--accent-hover:#60a8f0;
  --btn-bg:#3068b0;--btn-hover:#4a80d0;--btn-text:#fff;
  --btn-danger:#b05050;--btn-danger-hover:#d06060;
  --safe:#60c0a0;--likely:#98b8e0;--review:#c8b840;--keep:#d4745c;
  --progress-bg:#2a4060;--empty:#385070;
}
body.theme-sunset{
  --bg:#1d1418;--bg-card:#2d1a20;--bg-input:#1d1418;--border:#5a3040;
  --text:#e8c8c8;--text-secondary:#b07080;--text-heading:#f0c0c0;
  --accent:#e07050;--accent-hover:#f08060;
  --btn-bg:#c05040;--btn-hover:#e06850;--btn-text:#fff;
  --btn-danger:#a84060;--btn-danger-hover:#c85070;
  --safe:#80b860;--likely:#c898b0;--review:#d4a040;--keep:#e06050;
  --progress-bg:#5a3040;--empty:#604050;
}
body.theme-lavender{
  --bg:#1a1428;--bg-card:#2a2038;--bg-input:#1a1428;--border:#4a3068;
  --text:#d0c8e8;--text-secondary:#8878b0;--text-heading:#e0d8f8;
  --accent:#9070d0;--accent-hover:#a888e8;
  --btn-bg:#7058b0;--btn-hover:#8870d0;--btn-text:#fff;
  --btn-danger:#a05060;--btn-danger-hover:#c06070;
  --safe:#80c080;--likely:#b898e0;--review:#d0b040;--keep:#d4747c;
  --progress-bg:#4a3068;--empty:#504070;
}
body.theme-mono{
  --bg:#f0f0f0;--bg-card:#fff;--bg-input:#fff;--border:#ccc;
  --text:#333;--text-secondary:#888;--text-heading:#111;
  --accent:#555;--accent-hover:#333;
  --btn-bg:#555;--btn-hover:#333;--btn-text:#fff;
  --btn-danger:#c04040;--btn-danger-hover:#a03030;
  --safe:#3a8a3a;--likely:#7040a0;--review:#b08020;--keep:#c04040;
  --progress-bg:#ddd;--empty:#999;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--text);max-width:960px;margin:0 auto;padding:20px}
h1{color:var(--accent);font-size:24px;margin-bottom:8px}
.sub{color:var(--text-secondary);font-size:14px;margin-bottom:20px}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
.card h2{font-size:16px;color:var(--text-heading);margin-bottom:12px}
input,select,button{padding:5px 10px;border:1px solid var(--border);border-radius:6px;background:var(--bg-input);color:var(--text);font-size:14px}
input#path{width:380px;max-width:60vw;padding-right:22px}
button.clear{position:absolute;right:2px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--text-secondary);font-size:18px;cursor:pointer;padding:0 4px;line-height:1}
button.clear:hover{color:var(--keep)}
button{background:var(--btn-bg);color:var(--btn-text);cursor:pointer;border-color:var(--btn-bg)}
button:hover:not(:disabled){background:var(--btn-hover)}
button:disabled{opacity:.5;cursor:not-allowed}
button.cancel{background:var(--btn-danger);border-color:var(--btn-danger)}
button.cancel:hover:not(:disabled){background:var(--btn-danger-hover)}
select{width:60px} select#provider{width:110px}
label.chk{font-size:13px;color:var(--text);cursor:pointer;margin:0 6px}
label.chk input{width:auto;margin:0 3px 0 0;vertical-align:middle;padding:0}
table{width:100%;table-layout:fixed;border-collapse:collapse;margin-top:12px}
th,td{padding:6px 8px;text-align:left;border-bottom:1px solid var(--border);font-size:13px;white-space:nowrap}
th{color:var(--text-secondary);font-weight:600}
th:nth-child(1),td:nth-child(1){width:30px;text-align:center;padding:6px 2px}
th:nth-child(2),td:nth-child(2){width:30%}
th:nth-child(3),td:nth-child(3){width:10%}
th:nth-child(4),td:nth-child(4){width:10%}
th:nth-child(5),td:nth-child(5){width:10%}
th:nth-child(6),td:nth-child(6){width:40%}
tr{min-height:36px}
.cell-scroll{overflow-x:auto;white-space:nowrap;max-width:100%;padding:4px 0}
.cell-scroll::-webkit-scrollbar{height:6px}
.cell-scroll::-webkit-scrollbar-thumb{background:var(--text-secondary);border-radius:2px}
.reason-scroll{overflow-y:auto;white-space:normal;word-break:break-all;max-height:54px;line-height:1.4}
.reason-scroll::-webkit-scrollbar{width:4px}
.reason-scroll::-webkit-scrollbar-thumb{background:var(--text-secondary);border-radius:2px}
.safe{color:var(--safe)}.likely{color:var(--likely)}.review{color:var(--review)}.keep{color:var(--keep)}
.progress{height:4px;background:var(--progress-bg);border-radius:2px;margin:10px 0}
.progress-bar{height:100%;background:var(--btn-bg);border-radius:2px;transition:width .3s}
.progress-bar.cancelled{background:var(--btn-danger)}
#status{color:var(--text-secondary);font-size:13px;margin-top:8px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:16px}
.stat{background:var(--bg-input);border:1px solid var(--border);border-radius:6px;padding:10px;text-align:center}
.stat .num{font-size:24px;font-weight:700}
.stat .label{font-size:11px;color:var(--text-secondary);margin-top:4px}
.empty{text-align:center;color:var(--empty);padding:40px 0;font-size:14px}
td a{color:var(--accent);text-decoration:none;cursor:pointer}
td a:hover{text-decoration:underline}
@media(max-width:768px){
  body{padding:10px;max-width:100%}
  h1{font-size:18px}
  input,select,button{font-size:16px;padding:8px 12px}
  input#path{width:100%;max-width:100%;box-sizing:border-box}
  #scanBtn,#scanBtn+label{margin-top:8px}
  th,td{font-size:11px;padding:4px}
  th:nth-child(4),td:nth-child(4),th:nth-child(5),td:nth-child(5){display:none}
  th:nth-child(2),td:nth-child(2){width:40%}
  th:nth-child(6),td:nth-child(6){width:45%}
  .summary{grid-template-columns:repeat(3,1fr);gap:6px}
  .stat .num{font-size:18px}
  .stat .label{font-size:10px}
}
</style></head>
<body>
<div style="display:flex;justify-content:space-between;align-items:flex-start">
<div>
<h1>AI 磁盘清理工具</h1>
<div class="sub">扫描 → AI 分析 → 安全清理</div>
</div>
<select id="themeSelect" onchange="switchTheme(this.value)" style="width:auto;margin-top:4px">
<option value="dark">暗黑</option>
<option value="mono">极简</option>
<option value="gold">鎏金</option>
<option value="forest">森林</option>
<option value="ocean">海洋</option>
<option value="sunset">日落</option>
<option value="lavender">薰衣草</option>
</select>
</div>

<div class="card">
  <h2>扫描磁盘</h2>
  <div style="margin-bottom:10px">
    <span style="position:relative;display:inline-block">
      <input id="path" placeholder="输入目录路径" oninput="saveState()">
      <button class="clear" onclick="$('path').value='';saveState()" title="清空">&#xD7;</button>
    </span>
    <select id="top"><option value="50">50</option><option value="100">100</option><option value="200">200</option><option value="500">500</option><option value="1000">1000</option></select>
    <label class="chk"><input type="checkbox" id="recursive">子目录</label>
    <button id="scanBtn" onclick="handleScan()">开始分析</button>
    <label class="chk" id="aiLabel" title="需先配置 API Key"><input type="checkbox" id="useAI" onchange="toggleAI()" disabled>AI</label>
    <select id="provider" disabled></select>
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
function switchTheme(t){
  document.body.className = t==='dark'?'':'theme-'+t;
  localStorage.setItem('dc_theme',t);
  $('themeSelect').value=t;
}
function toggleAI() {
  $('provider').disabled = !$('useAI').checked;
}
function fmtSize(b) {if(b>1e9)return (b/1e9).toFixed(2)+' GB';return (b/1e6).toFixed(1)+' MB'}
const DECO={'safe_to_delete':'safe','likely_safe':'likely','needs_review':'review','keep':'keep','critical':'keep'}
const LBL={safe_to_delete:'可删除',likely_safe:'概率可删',needs_review:'需确认',keep:'保留',critical:'禁止删除'}
const SRC={cache:'缓存',rule:'规则',ai:'AI',local:'本地分析','rule+cache':'规则+缓存','ai+cache':'AI+缓存','local+cache':'本地分析+缓存',dependency:'依赖分析',fingerprint:'指纹库',cancelled:'已取消',error:'异常',ai_cluster:'AI聚类',ai_cross_cluster:'AI交叉聚类'}

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
  toggleAI();
  const savedPath = localStorage.getItem('dc_path');
  if (savedPath) {
    const saved = localStorage.getItem('dc_results');
    if (saved) {
      try {
        const data = JSON.parse(saved);
        if (data.results && data.results.length > 0 && data.results[0].size === 0 && data.results[0].decision === '') {
          localStorage.removeItem('dc_results');
        } else {
          showResults(data);
        }
      } catch(e) {}
    }
  }
}

// 检测 AI 是否已配置
const AI_NAMES={deepseek:'DeepSeek',openai:'OpenAI',claude:'Claude',gemini:'Gemini',ollama:'Ollama (本地)'};
async function checkAIConfig() {
  const r = await api('/api/check-ai', {});
  if (r.configured && r.providers.length > 0) {
    $('useAI').disabled = false;
    $('aiLabel').title = '启用云端AI可获得更准确的分析结果';
    const sel = $('provider');
    sel.innerHTML = r.providers.map(p => `<option value="${p}">${AI_NAMES[p]||p}</option>`).join('');
    if (r.providers.length === 1) sel.value = r.providers[0];
    // 恢复用户上次的选择
    const saved = localStorage.getItem('dc_provider');
    if (saved && r.providers.includes(saved)) sel.value = saved;
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
    if (_ctrl) {
      if (_ctrl._es) { _ctrl._es.close(); _ctrl._es = null; }
      _ctrl.abort();
    }
    _ctrl = null;
    _busy = false;
    api('/api/cancel', {});  // 通知后端取消引擎
    $('progressBar').style.width = '0%';
    $('progressBar').classList.add('cancelled');
    $('status').textContent = '已取消';
    btn.textContent = '开始分析';
    btn.className = '';
    setTimeout(() => { $('progressContainer').style.display = 'none'; }, 1500);
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

  let _es = null;  // EventSource 引用，供取消用
  let _results = [];
  try {
    const p=cleanPath($('path').value), t=parseInt($('top').value), r=$('recursive').checked,
          ai=$('useAI').checked, prov=$('provider').value, f=false;
    if (!p) { $('status').textContent = '请输入目录路径'; $('progressContainer').style.display = 'none'; return; }
    await api('/api/scan', {path:p,top:t,recursive:r,use_ai:ai,provider:prov,force:f});
    if (!_busy) { cancelled(); return; }

    // 初始化空表格
    $('resultsBody').innerHTML =
      `<div style="margin:8px 0;display:flex;justify-content:space-between;align-items:center">
         <span>
           <select id="filterSize" onchange="applyFilters()" style="width:auto;margin-right:6px">
             <option value="0">全部大小</option>
             <option value="-1">< 1 MB</option>
             <option value="1">>1 MB</option>
             <option value="10">>10 MB</option>
             <option value="100">>100 MB</option>
             <option value="1024">>1 GB</option>
           </select>
           <select id="filterDecision" onchange="applyFilters()" style="width:auto;margin-right:6px">
             <option value="all">全部判定</option>
             <option value="safe_to_delete">可删除</option>
             <option value="likely_safe">概率可删</option>
             <option value="needs_review">需确认</option>
             <option value="keep">保留</option>
           </select>
           <span style="position:relative;display:inline-block;margin-right:6px">
             <input id="filterFile" placeholder="文件名" oninput="$('clearFile').style.display=this.value?'inline':'none'" style="width:160px;padding-right:20px">
             <button id="clearFile" onclick="$('filterFile').value='';$('clearFile').style.display='none';applyFilters()" title="清空" style="display:none;position:absolute;right:2px;top:50%;transform:translateY(-50%);background:none;border:none;color:#8b949e;font-size:14px;cursor:pointer;padding:0 4px;line-height:1">&#xD7;</button>
           </span>
           <span style="position:relative;display:inline-block;margin-right:6px">
             <input id="filterReason" placeholder="理由" oninput="$('clearReason').style.display=this.value?'inline':'none'" style="width:160px;padding-right:20px">
             <button id="clearReason" onclick="$('filterReason').value='';$('clearReason').style.display='none';applyFilters()" title="清空" style="display:none;position:absolute;right:2px;top:50%;transform:translateY(-50%);background:none;border:none;color:#8b949e;font-size:14px;cursor:pointer;padding:0 4px;line-height:1">&#xD7;</button>
           </span>
           <button onclick="applyFilters()" style="margin-left:4px">筛选</button>
         </span>
         <span>
           <button onclick="cleanSelected()">清理选中</button>
           <button onclick="getReport()" style="margin-left:6px">导出报告</button>
         </span>
       </div>
       <div style="overflow-x:auto"><table id="resultsTable">
         <thead><tr><th><input type="checkbox" onchange="toggleAll(this)" title="全选/取消全选"></th><th>文件</th><th>大小</th><th>判定</th><th>来源</th><th>理由</th></tr></thead>
         <tbody id="resultsTbody"></tbody></table></div>`;

    // SSE 流式分析
    const qs = `path=${encodeURIComponent(p)}&top=${t}&recursive=${r}&use_ai=${ai}&provider=${prov}&force=${f}`;
    _es = new EventSource(`/api/analyze-stream?${qs}`);
    _ctrl._es = _es;  // 挂到 AbortController 上供取消

    _es.onmessage = (e) => {
      const d = JSON.parse(e.data);
      if (d.type === 'progress') {
        const pct = 20 + Math.round((d.current / d.total) * 80);
        $('progressBar').style.width = pct + '%';
        $('status').textContent = (ai ? 'AI 分析' : '本地分析') + `: ${d.current}/${d.total}`;
        appendResult(d.result);
        _results.push(d.result);
      } else if (d.type === 'done') {
        _es.close(); _es = null;
        $('progressBar').style.width = '100%';
        $('status').textContent = '完成';
        finishResults(d.stats, d.summary);
        localStorage.setItem('dc_results', JSON.stringify({results: _results, stats: d.stats, summary: d.summary}));
        setTimeout(() => { $('progressContainer').style.display = 'none'; }, 1500);
      } else if (d.type === 'error') {
        _es.close(); _es = null;
        $('status').textContent = '错误: ' + d.message;
      } else if (d.type === 'cancelled') {
        _es.close(); _es = null;
        $('progressBar').style.width = d.current/d.total*80+20 + '%';
        cancelled();
        setTimeout(() => { $('progressContainer').style.display = 'none'; }, 1500);
      }
    };
    _es.onerror = () => {
      if (_es) { _es.close(); _es = null; }
      $('status').textContent = '连接中断';
    };
    // 等待流完成（用 Promise 包装 EventSource）
    await new Promise((resolve) => {
      const check = setInterval(() => { if (!_es) { clearInterval(check); resolve(); } }, 200);
    });
  } catch(e) {
    console.log('handleScan error:', e);
    $('status').textContent = '错误: ' + e.message;
  } finally {
    if (_es) { _es.close(); _es = null; }
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

function appendResult(r) {
  const showDir = $('recursive').checked;
  const row = `<tr data-size-mb="${r.size_mb||0}" data-decision="${r.decision||''}" data-reason="${escAttr(r.reason||'')}" data-name="${escAttr(r.name||'')}">
    <td><input type="checkbox" value="${escAttr(r.path)}" ${r.decision==='safe_to_delete'?'checked':''}></td>
    <td><div class="cell-scroll"><a href="#" class="filelink" data-path="${escAttr(r.path)}" title="在资源管理器中打开并选中">${escHtml(showDir?r.path.replace(/\\\\/g,'/').replace(cleanPath($('path').value).replace(/\\\\/g,'/').replace(/\\/$/,'')+'/',''):r.name)}</a></div></td>
    <td>${fmtSize(r.size)}</td>
    <td class="${DECO[r.decision]||''}">${LBL[r.decision]||r.decision}</td>
    <td>${SRC[r.source]||r.source||''}</td>
    <td><div class="reason-scroll">${escHtml(r.reason||'')}</div></td>
  </tr>`;
  const tbody = $('resultsTbody');
  if (tbody) tbody.insertAdjacentHTML('beforeend', row);
}

function finishResults(stats, summary) {
  $('summary').innerHTML =
    `<div class="stat"><div class="num safe">${summary.safe||0}</div><div class="label">可清理</div></div>
     <div class="stat"><div class="num likely">${summary.likely||0}</div><div class="label">可能可清理</div></div>
     <div class="stat"><div class="num review">${summary.review||0}</div><div class="label">需确认</div></div>
     <div class="stat"><div class="num keep">${summary.keep||0}</div><div class="label">建议保留</div></div>
     <div class="stat"><div class="num">${stats.cache_hits||0}</div><div class="label">缓存命中</div></div>
     <div class="stat"><div class="num">${stats.ai_calls||0}</div><div class="label">AI 调用</div></div>`;
  // 排序：同目录聚拢
  const tbody = $('resultsTbody');
  if (!tbody) return;
  const rows = [...tbody.querySelectorAll('tr')];
  // 简单排序：按 depth + decision 重组 DOM
  const scanRoot = cleanPath($('path').value).replace(/\\\\/g,'/');
  rows.sort((a,b) => {
    const pa = (a.querySelector('.filelink')?.dataset.path||'').replace(/\\\\/g,'/');
    const pb = (b.querySelector('.filelink')?.dataset.path||'').replace(/\\\\/g,'/');
    // 去掉扫描根路径后比较深度
    const ra = pa.replace(scanRoot.replace(/\\/$/,'')+'/','');
    const rb = pb.replace(scanRoot.replace(/\\/$/,'')+'/','');
    const da = ra.split('/').length, db = rb.split('/').length;
    return da - db || ra.localeCompare(rb);
  });
  rows.forEach(r => tbody.appendChild(r));
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
    `<div style="margin:8px 0;display:flex;justify-content:space-between;align-items:center">
         <span>
           <select id="filterSize" onchange="applyFilters()" style="width:auto;margin-right:6px">
             <option value="0">全部大小</option>
             <option value="-1">< 1 MB</option>
             <option value="1">>1 MB</option>
             <option value="10">>10 MB</option>
             <option value="100">>100 MB</option>
             <option value="1024">>1 GB</option>
           </select>
           <select id="filterDecision" onchange="applyFilters()" style="width:auto;margin-right:6px">
             <option value="all">全部判定</option>
             <option value="safe_to_delete">可删除</option>
             <option value="likely_safe">概率可删</option>
             <option value="needs_review">需确认</option>
             <option value="keep">保留</option>
           </select>
           <span style="position:relative;display:inline-block;margin-right:6px">
             <input id="filterFile" placeholder="文件名" oninput="$('clearFile').style.display=this.value?'inline':'none'" style="width:160px;padding-right:20px">
             <button id="clearFile" onclick="$('filterFile').value='';$('clearFile').style.display='none';applyFilters()" title="清空" style="display:none;position:absolute;right:2px;top:50%;transform:translateY(-50%);background:none;border:none;color:#8b949e;font-size:14px;cursor:pointer;padding:0 4px;line-height:1">&#xD7;</button>
           </span>
           <span style="position:relative;display:inline-block;margin-right:6px">
             <input id="filterReason" placeholder="理由" oninput="$('clearReason').style.display=this.value?'inline':'none'" style="width:160px;padding-right:20px">
             <button id="clearReason" onclick="$('filterReason').value='';$('clearReason').style.display='none';applyFilters()" title="清空" style="display:none;position:absolute;right:2px;top:50%;transform:translateY(-50%);background:none;border:none;color:#8b949e;font-size:14px;cursor:pointer;padding:0 4px;line-height:1">&#xD7;</button>
           </span>
           <button onclick="applyFilters()" style="margin-left:4px">筛选</button>
         </span>
         <span>
           <button onclick="cleanSelected()">清理选中</button>
           <button onclick="getReport()" style="margin-left:6px">导出报告</button>
         </span>
       </div>
     <div style="overflow-x:auto"><table id="resultsTable">
       <thead><tr><th><input type="checkbox" onchange="toggleAll(this)" title="全选/取消全选"></th><th>文件</th><th>大小</th><th>判定</th><th>来源</th><th>理由</th></tr></thead>
       <tbody>${results.map(r=>`<tr data-size-mb="${r.size_mb||0}" data-decision="${r.decision||''}" data-reason="${escAttr(r.reason||'')}" data-name="${escAttr(r.name||'')}">
         <td><input type="checkbox" value="${escAttr(r.path)}" ${r.decision==='safe_to_delete'?'checked':''}></td>
         <td><div class="cell-scroll"><a href="#" class="filelink" data-path="${escAttr(r.path)}" title="在资源管理器中打开并选中">${escHtml(showDir?r.path.replace(/\\\\/g,'/').replace(cleanPath($('path').value).replace(/\\\\/g,'/').replace(/\\/$/,'')+'/',''):r.name)}</a></div></td>
         <td>${fmtSize(r.size)}</td>
         <td class="${DECO[r.decision]||''}">${LBL[r.decision]||r.decision}</td>
         <td>${SRC[r.source]||r.source||''}</td>
         <td><div class="reason-scroll">${escHtml(r.reason||'')}</div></td>
       </tr>`).join('')}</tbody></table></div>`;
}

function updateSelectAll(){
  const visible = [...document.querySelectorAll('#resultsTable tbody tr')].filter(tr => tr.style.display !== 'none');
  const allChecked = visible.length > 0 && visible.every(tr => tr.querySelector('input[type=checkbox]').checked);
  const cb = document.querySelector('#resultsTable thead input[type=checkbox]');
  if (cb) cb.checked = allChecked;
}
function applyFilters(){
  const minMB = parseFloat($('filterSize').value);
  const dec = $('filterDecision').value;
  const reStr = $('filterReason')?.value || '';
  const fileStr = $('filterFile')?.value || '';
  let re = null, fileRe = null;
  try { if (reStr) re = new RegExp(reStr, 'i'); } catch(e) {}
  try { if (fileStr) fileRe = new RegExp(fileStr, 'i'); } catch(e) {}
  const rows = document.querySelectorAll('#resultsTable tbody tr');
  let visibleCount = 0;
  rows.forEach(tr => {
    const sizeMB = parseFloat(tr.dataset.sizeMb) || 0;
    const decision = tr.dataset.decision || '';
    const reason = tr.dataset.reason || '';
    const name = tr.dataset.name || '';
    const sizeOk = minMB < 0 ? sizeMB < 1 : sizeMB >= minMB;
    const decOk = dec === 'all' || decision === dec || (dec === 'keep' && (decision === 'keep' || decision === 'critical'));
    const reOk = !re || re.test(reason);
    const fileOk = !fileRe || fileRe.test(name);
    const show = sizeOk && decOk && reOk && fileOk;
    tr.style.display = show ? '' : 'none';
    if (show) visibleCount++;
    // 隐藏行取消勾选
    if (!show) tr.querySelector('input[type=checkbox]').checked = false;
  });
  const cb = document.querySelector('#resultsTable thead input[type=checkbox]');
  if (cb) cb.checked = false;
  $('status').textContent = '筛选结果: ' + visibleCount + ' 个文件';
}
function toggleAll(cb){
  document.querySelectorAll('#resultsTable tbody tr').forEach(tr => {
    if (tr.style.display !== 'none') tr.querySelector('input[type=checkbox]').checked = cb.checked;
  });
}
function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function escAttr(s){return String(s).replace(/"/g,'&quot;')}

async function cleanSelected() {
  const files = [...document.querySelectorAll('#resultsTable tbody tr')]
    .filter(tr => tr.style.display !== 'none')
    .map(tr => tr.querySelector('input[type=checkbox]'))
    .filter(cb => cb && cb.checked)
    .map(cb => cb.value);
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
switchTheme(localStorage.getItem('dc_theme')||'dark');
loadState();
checkAIConfig();
// 输入变化自动保存
['path','top','recursive','useAI','provider'].forEach(id=>{
  $(id).addEventListener('change',saveState);
  $(id).addEventListener('input',saveState);
});
// 事件委托：文件链接 + 勾选框联动
$('resultsBody').addEventListener('click',async e=>{
  const a=e.target.closest('.filelink');
  if(a){
    e.preventDefault();
    const r=await api('/api/open-file',{path:a.dataset.path});
    if(r.error)alert(r.error);
    return;
  }
  if(e.target.type==='checkbox' && e.target.closest('tbody')){
    updateSelectAll();
  }
});
</script></body></html>"""


class GUIHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器"""

    engine: AnalysisEngine | None = None
    last_results: list[dict] = []

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._respond_html(GUI_HTML)
        elif self.path.startswith("/api/analyze-stream"):
            # EventSource GET 请求——从 query string 解析参数
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            data = {k: v[0] for k, v in qs.items()}
            # 类型转换
            if "top" in data:
                data["top"] = int(data["top"])
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
            model_defaults = {"deepseek": "deepseek-v4-flash", "openai": "gpt-4o-mini", "claude": "claude-3-haiku-20240307", "gemini": "gemini-1.5-flash", "ollama": "qwen2.5:1.5b"}
            eng = AnalysisEngine(db, ai_provider=ai_provider, ai_model=model_defaults.get(provider, ""))
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

    def _handle_analyze_stream(self, data: dict):
        """SSE 流式分析——逐文件推送进度"""
        path = data.get("path", ".")
        top = data.get("top", 100)
        recursive = data.get("recursive", True)
        use_ai = data.get("use_ai", False)
        provider = data.get("provider", "deepseek")
        force = data.get("force", False)

        if not os.path.exists(path):
            self._respond_json({"error": f"路径不存在: {path}"})
            return

        # SSE 响应头
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        db = _get_db()
        results_buf: list[dict] = []
        try:
            ai_provider = provider if use_ai else "local"
            model_defaults = {"deepseek": "deepseek-v4-flash", "openai": "gpt-4o-mini", "claude": "claude-3-haiku-20240307", "gemini": "gemini-1.5-flash", "ollama": "qwen2.5:1.5b"}
            eng = AnalysisEngine(db, ai_provider=ai_provider, ai_model=model_defaults.get(provider, ""))
            GUIHandler.engine = eng

            for evt in eng.analyze_directory_stream(path, top_n=top, recursive=recursive, force=force):
                if evt["type"] == "cancelled":
                    self._sse_send({"type": "cancelled", "current": evt["current"], "total": evt["total"]})
                    break
                results_buf.append(evt["result"])
                self._sse_send({"type": "progress", "current": evt["current"], "total": evt["total"], "result": evt["result"]})

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
            self._respond_json({"error": "文件不存在"})
            return
        try:
            subprocess.run(
                ["explorer", "/select,", os.path.abspath(path)],
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            self._respond_json({"status": "ok"})
        except Exception as e:
            self._respond_json({"error": str(e)})

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

    server = ThreadingHTTPServer(("0.0.0.0", port), GUIHandler)
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
