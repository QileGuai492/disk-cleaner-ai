const DC_TOKEN = "__DC_TOKEN__";
let _busy = false, _ctrl = null;
let _allResults = [];
let _chatSession = null, _chatTarget = '', _chatScope = 'scan', _chatKey = '', _chatES = null;
const $=id=>document.getElementById(id);

async function api(path, data) {
  try {const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-DC-Token':DC_TOKEN},body:JSON.stringify(data),signal:_ctrl?.signal});return r.json()}
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
const SRC={cache:'缓存',rule:'规则',ai:'AI',local:'本地分析',degraded:'本地降级','rule+cache':'规则+缓存','ai+cache':'AI+缓存','local+cache':'本地分析+缓存',dependency:'依赖分析',fingerprint:'指纹库',cancelled:'已取消',error:'异常',ai_cluster:'AI聚类',ai_cross_cluster:'AI交叉聚类'}

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
  return p.trim().replace(/^["'“”‘’]+|["'“”‘’]+$/g, '');
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
  _allResults = [];
  resetChatState();
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
            <button onclick="showBackups()" style="margin-left:6px">恢复备份</button>
            <button onclick="openChat('folder', cleanPath($('path').value))" style="margin-left:6px">评估目录</button>
            <button onclick="openChat('scan','')" style="margin-left:6px">清理顾问</button>
            <button onclick="showDirView()" style="margin-left:6px">目录视图</button>
         </span>
       </div>
       <div style="overflow-x:auto"><table id="resultsTable">
         <thead><tr><th><input type="checkbox" onchange="toggleAll(this)" title="全选/取消全选"></th><th>文件</th><th>大小</th><th>判定</th><th>来源</th><th>理由</th></tr></thead>
         <tbody id="resultsTbody"></tbody></table></div>`;

    // SSE 流式分析
    const qs = `path=${encodeURIComponent(p)}&top=${t}&recursive=${r}&use_ai=${ai}&provider=${prov}&force=${f}`;
    _es = new EventSource(`/api/analyze-stream?${qs}&token=${encodeURIComponent(DC_TOKEN)}`);
    _ctrl._es = _es;  // 挂到 AbortController 上供取消

    _es.onmessage = (e) => {
      const d = JSON.parse(e.data);
      if (d.type === 'progress') {
        const pct = 20 + Math.round((d.current / d.total) * 80);
        $('progressBar').style.width = pct + '%';
        $('status').textContent = (ai ? 'AI 分析' : '本地分析') + `: ${d.current}/${d.total}`;
        appendResult(d.result);
        _results.push(d.result);
        _allResults.push(d.result);
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
    <td><input type="checkbox" value="${escAttr(r.path)}" ${(r.decision==='keep'||r.decision==='critical')?'disabled':''}></td>
    <td><div class="cell-scroll"><a href="#" class="filelink" data-path="${escAttr(r.path)}" title="在资源管理器中打开并选中">${escHtml(showDir?r.path.replace(/\\/g,'/').replace(cleanPath($('path').value).replace(/\\/g,'/').replace(/\/$/,'')+'/',''):r.name)}</a> <button class="ask-btn" data-path="${escAttr(r.path)}" title="问清理顾问">问</button></div></td>
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
  const scanRoot = cleanPath($('path').value).replace(/\\/g,'/');
  rows.sort((a,b) => {
    const pa = (a.querySelector('.filelink')?.dataset.path||'').replace(/\\/g,'/');
    const pb = (b.querySelector('.filelink')?.dataset.path||'').replace(/\\/g,'/');
    // 去掉扫描根路径后比较深度
    const ra = pa.replace(scanRoot.replace(/\/$/,'')+'/','');
    const rb = pb.replace(scanRoot.replace(/\/$/,'')+'/','');
    const da = ra.split('/').length, db = rb.split('/').length;
    return da - db || ra.localeCompare(rb);
  });
  rows.forEach(r => tbody.appendChild(r));
}

function showResults(data) {
  const results = data.results || [], stats = data.stats || {}, summary = data.summary || {};
  _allResults = results.slice();
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
            <button onclick="showBackups()" style="margin-left:6px">恢复备份</button>
            <button onclick="openChat('folder', cleanPath($('path').value))" style="margin-left:6px">评估目录</button>
            <button onclick="openChat('scan','')" style="margin-left:6px">清理顾问</button>
            <button onclick="showDirView()" style="margin-left:6px">目录视图</button>
         </span>
       </div>
     <div style="overflow-x:auto"><table id="resultsTable">
       <thead><tr><th><input type="checkbox" onchange="toggleAll(this)" title="全选/取消全选"></th><th>文件</th><th>大小</th><th>判定</th><th>来源</th><th>理由</th></tr></thead>
       <tbody>${results.map(r=>`<tr data-size-mb="${r.size_mb||0}" data-decision="${r.decision||''}" data-reason="${escAttr(r.reason||'')}" data-name="${escAttr(r.name||'')}">
         <td><input type="checkbox" value="${escAttr(r.path)}" ${(r.decision==='keep'||r.decision==='critical')?'disabled':''}></td>
         <td><div class="cell-scroll"><a href="#" class="filelink" data-path="${escAttr(r.path)}" title="在资源管理器中打开并选中">${escHtml(showDir?r.path.replace(/\\/g,'/').replace(cleanPath($('path').value).replace(/\\/g,'/').replace(/\/$/,'')+'/',''):r.name)}</a> <button class="ask-btn" data-path="${escAttr(r.path)}" title="问清理顾问">问</button></div></td>
         <td>${fmtSize(r.size)}</td>
         <td class="${DECO[r.decision]||''}">${LBL[r.decision]||r.decision}</td>
         <td>${SRC[r.source]||r.source||''}</td>
         <td><div class="reason-scroll">${escHtml(r.reason||'')}</div></td>
       </tr>`).join('')}</tbody></table></div>`;
}

function updateSelectAll(){
  const visible = [...document.querySelectorAll('#resultsTable tbody tr')]
    .filter(tr => tr.style.display !== 'none' && !tr.querySelector('input[type=checkbox]').disabled);
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
    const box = tr.querySelector('input[type=checkbox]');
    if (tr.style.display !== 'none' && box && !box.disabled) box.checked = cb.checked;
  });
}
function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function escAttr(s){return String(s).replace(/"/g,'&quot;')}

async function cleanSelected() {
  const files = [...document.querySelectorAll('#resultsTable tbody tr')]
    .filter(tr => tr.style.display !== 'none')
    .map(tr => tr.querySelector('input[type=checkbox]'))
    .filter(cb => cb && cb.checked && !cb.disabled)
    .map(cb => cb.value);
  if (!files.length) return alert('请先勾选文件');
  if (!confirm('确认清理 ' + files.length + ' 个文件？')) return;
  const r = await api('/api/clean', {files});
  if (r.error) return alert(r.error);
  let msg = `已移动 ${r.moved || 0} 个文件到备份区`;
  if (r.freed) msg += `，实际释放 ${fmtSize(r.freed)}`;
  if (r.skipped) msg += `，跳过 ${r.skipped} 个`;
  if (r.batch_id) msg += `
备份批次：${r.batch_id}`;
  if (r.warning) msg += `

${r.warning}`;
  alert(msg);
}

async function showBackups(){
  const r = await api('/api/backups', {});
  if(r.error) return alert(r.error);
  const batches = r.batches || [];
  if(!batches.length) return alert('暂无备份批次');
  const lines = batches.map(b =>
    `${b.batch_id}  ${b.file_count} 个文件  ${fmtSize(b.total_bytes)}  ${b.created_at.slice(0,19)}`);
  const batchId = prompt('输入要恢复的批次 ID：\n\n' + lines.join('\n'));
  if(!batchId) return;
  if(!confirm('确认恢复批次 ' + batchId + '？已存在的目标文件不会被覆盖。')) return;
  const restored = await api('/api/backup/restore', {batch_id:batchId});
  if(restored.error) return alert(restored.error);
  alert(`已恢复 ${restored.restored} 个，失败 ${restored.failed} 个`);
}

async function getReport() {
  const r = await api('/api/report', {});
  if (r.error) return alert(r.error);
  const w = window.open('', '_blank');
  w.document.write(r.html);
  w.document.close();
}
// ---------- 目录视图 ----------
function showDirView(){
  if(!_allResults.length){ alert('请先分析目录'); return; }
  const groups = {};
  _allResults.forEach(r=>{
    let p = String(r.path || '').replace(/\\/g,'/');
    const dir = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : p;
    if(!groups[dir]) groups[dir] = {files:0, size:0, safe:0, keep:0};
    groups[dir].files += 1;
    groups[dir].size += Number(r.size || 0);
    if(r.decision === 'safe_to_delete' || r.decision === 'likely_safe') groups[dir].safe += 1;
    if(r.decision === 'keep' || r.decision === 'critical') groups[dir].keep += 1;
  });
  const rows = Object.entries(groups).sort((a,b)=>b[1].size-a[1].size).map(([dir,v])=>
    `<tr><td style="word-break:break-all">${escHtml(dir)}</td><td>${v.files}</td>` +
    `<td>${fmtSize(v.size)}</td><td>${v.safe}</td><td>${v.keep}</td>` +
    `<td><button class="dir-ask" data-dir="${escAttr(dir)}">评估</button></td></tr>`).join('');
  $('dirBody').innerHTML =
    `<table><thead><tr><th>目录</th><th>文件数</th><th>大小</th><th>可清理</th><th>保留</th><th></th></tr></thead>` +
    `<tbody>${rows}</tbody></table>`;
  $('dirModal').style.display = 'flex';
}
function closeDirView(){ $('dirModal').style.display = 'none'; }
document.addEventListener('click', e=>{
  const btn = e.target.closest && e.target.closest('.dir-ask');
  if(btn){ closeDirView(); openChat('folder', btn.dataset.dir); }
});

// ---------- 清理顾问 ----------
function normPath(p){return String(p||'').replace(/\\/g,'/').replace(/\/$/,'').toLowerCase()}
function chatScopeLabel(scope){
  return {file:'单文件',folder:'文件夹',selection:'多选',scan:'本次扫描'}[scope]||scope;
}
function chatKey(scope, target){ return `${scope}::${normPath(target)}`; }
function openChat(scope, target){
  if(!_allResults.length){ alert('请先分析目录，再打开清理顾问'); return; }
  scope = scope || 'scan';
  target = target || '';
  if(scope === 'folder' && target && _allResults.some(r=>normPath(r.path)===normPath(target))) scope = 'file';
  const key = chatKey(scope, target);
  // 叉号只是收起面板；同一范围重新打开时复用会话和消息。
  if(_chatSession && _chatKey === key){
    $('chatPanel').classList.add('open');
    $('chatMessages').scrollTop = $('chatMessages').scrollHeight;
    $('chatText').focus();
    return;
  }
  api('/api/chat/session', {scope, target}).then(r=>{
    if(r.error){ alert(r.error); return; }
    _chatSession = r.session;
    _chatTarget = r.session.target || target;
    _chatScope = scope;
    _chatKey = key;
    $('chatPanel').classList.add('open');
    $('chatContext').textContent =
      `${chatScopeLabel(scope)} · ${r.session.target || '本次扫描'} · ${r.session.file_count} 个文件 · ${r.session.total_mb} MB · ${r.session.verdict_label || ''}`;
    $('chatMessages').innerHTML = '';
    addChatMessage('assistant',
      `已读取本次扫描的 ${r.session.file_count} 个文件，共 ${r.session.total_mb} MB。\n` +
      `结论：${r.session.verdict_label || '需要确认'}\n${r.session.summary || ''}`);
    renderQuick(scope);
  });
}
function renderQuick(scope){
  const questions = scope === 'file'
    ? ['这个文件是做什么的？','删了会怎样？','能自动重建吗？','它和哪些文件有关？']
    : scope === 'folder'
      ? ['这个文件夹整体能删吗？','哪些能删、哪些必须留？','有没有同源目录？','建议搬迁还是清理？']
      : ['最值得清理的 10 项？','哪些判断最不可靠？','哪些误删风险最高？'];
  $('chatQuick').innerHTML = questions.map(q =>
    `<button onclick="quickAsk('${q}')">${escHtml(q)}</button>`).join('');
}
function quickAsk(text){ $('chatText').value = text; sendChat(); }
function addChatMessage(role, text){
  const div = document.createElement('div');
  div.className = 'chat-msg ' + role;
  div.textContent = text;
  $('chatMessages').appendChild(div);
  $('chatMessages').scrollTop = $('chatMessages').scrollHeight;
  return div;
}
function closeChat(){
  // 只隐藏，不销毁会话；再次打开同一范围会恢复对话。
  if(_chatES){ _chatES.close(); _chatES = null; }
  $('chatPanel').classList.remove('open');
}
function resetChatState(){
  if(_chatES){ _chatES.close(); _chatES = null; }
  _chatSession = null;
  _chatKey = '';
  _chatTarget = '';
  _chatScope = 'scan';
  $('chatPanel').classList.remove('open');
  $('chatMessages').innerHTML =
    '<div class="chat-msg assistant">我会根据本次扫描结果解释文件用途、评估文件夹，并检查跨目录关联。</div>';
}
function newChat(){
  const scope = _chatScope || 'scan';
  const target = _chatTarget || '';
  resetChatState();
  openChat(scope, target);
}
function renderChatAnswer(data){
  const box = _chatCurrent || addChatMessage('assistant','');
  box.textContent = '';
  const head = document.createElement('div');
  head.className = 'chat-verdict';
  head.textContent = `${data.verdict_label || data.verdict || ''} · 置信度 ${(data.confidence||0).toFixed(2)} · ${data.source === 'ai' ? 'AI' : '本地规则'}`;
  box.appendChild(head);
  const body = document.createElement('div');
  body.textContent = data.answer || '';
  box.appendChild(body);
  if(data.evidence && data.evidence.length){
    const details = document.createElement('details');
    details.className = 'chat-evidence';
    const summary = document.createElement('summary');
    summary.textContent = `证据（${data.evidence.length} 条）`;
    details.appendChild(summary);
    const ul = document.createElement('ul');
    data.evidence.forEach(item=>{
      const li = document.createElement('li');
      li.textContent = `${item.id} ${item.summary}`;
      ul.appendChild(li);
    });
    details.appendChild(ul);
    box.appendChild(details);
  }
  const actions = document.createElement('div');
  actions.className = 'chat-actions';
  (data.actions || []).forEach(action=>{
    const btn = document.createElement('button');
    btn.textContent = action.label || action.type;
    btn.onclick = () => chatAction(action.type);
    actions.appendChild(btn);
  });
  if(actions.children.length) box.appendChild(actions);
  const feedback = document.createElement('div');
  feedback.className = 'chat-feedback';
  const help = document.createElement('button');
  help.textContent = '有帮助';
  help.onclick = ()=>{
    try {
      localStorage.setItem('dc_chat_helpful', String(Number(localStorage.getItem('dc_chat_helpful')||0)+1));
    } catch(e) {}
    help.textContent = '已记录';
    help.disabled = true;
  };
  feedback.appendChild(help);
  feedback.appendChild(document.createTextNode('本地反馈，不上传内容'));
  box.appendChild(feedback);
  $('chatMessages').scrollTop = $('chatMessages').scrollHeight;
}
function sendChat(){
  if(!_chatSession){ openChat('scan',''); return; }
  const text = $('chatText').value.trim();
  if(!text) return;
  $('chatText').value = '';
  addChatMessage('user', text);
  _chatCurrent = addChatMessage('assistant', '正在读取证据...');
  const provider = $('useAI').checked ? $('provider').value : '';
  if(_chatES){ _chatES.close(); }
  const url = `/api/chat/stream?session_id=${encodeURIComponent(_chatSession.session_id)}` +
    `&text=${encodeURIComponent(text)}&provider=${encodeURIComponent(provider)}` +
    `&token=${encodeURIComponent(DC_TOKEN)}`;
  _chatES = new EventSource(url);
  let streamed = '';
  _chatES.onmessage = (e)=>{
    const d = JSON.parse(e.data);
    if(d.type === 'token'){
      streamed += d.text || '';
      if(_chatCurrent){ _chatCurrent.textContent = streamed; }
    } else if(d.type === 'answer'){
      renderChatAnswer(d);
    } else if(d.type === 'error'){
      if(_chatCurrent){ _chatCurrent.textContent = '错误：' + d.message; }
    } else if(d.type === 'done'){
      if(_chatES){ _chatES.close(); _chatES = null; }
    }
  };
  _chatES.onerror = ()=>{
    if(_chatCurrent){ _chatCurrent.textContent = '连接中断，请重试'; }
    if(_chatES){ _chatES.close(); _chatES = null; }
  };
}
async function requestChatPlan(){
  if(!_chatSession){ alert('请先打开清理顾问并完成一次问答'); return; }
  const r = await api('/api/chat/plan', {session_id:_chatSession.session_id, mode:'backup'});
  if(r.error){ alert(r.error); return; }
  const plan = r.plan || {};
  const paths = plan.paths || [];
  const lines = [
    `清理计划（未执行）`,
    `模式：${plan.mode || 'backup'} · 文件：${paths.length} 个 · 预计移动：${plan.total_mb || 0} MB`,
    `备份目录：${plan.backup_dir || ''}`,
  ];
  if(r.warning) lines.push(`注意：${r.warning}`);
  lines.push('', ...paths.slice(0,20));
  if(paths.length > 20) lines.push(`...另有 ${paths.length - 20} 个文件`);
  lines.push('', '这只是一个计划。请回到结果表勾选确认后，再使用“清理选中”。');
  addChatMessage('assistant', lines.join('\n'));
}
async function chatAction(type){
  if(type === 'draft_plan'){ await requestChatPlan(); }
  else if(type === 'open_folder'){
    const r = await api('/api/open-folder', {path:_chatTarget});
    if(r.error) alert(r.error);
  } else if(type === 'ask_user'){
    $('chatText').focus();
  }
}

function dismissWelcome(){
  $('welcome').style.display = 'none';
  try { localStorage.setItem('dc_welcome_seen', '1'); } catch(e) {}
}
if(!localStorage.getItem('dc_welcome_seen')){
  $('welcome').style.display = 'flex';
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
  const ask=e.target.closest('.ask-btn');
  if(ask){
    e.preventDefault();
    openChat('file', ask.dataset.path);
    return;
  }
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
