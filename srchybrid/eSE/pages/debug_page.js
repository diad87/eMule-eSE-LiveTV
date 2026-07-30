'use strict';

function handle(url, _req, res) {
  if (url.pathname !== '/debug' && url.pathname !== '/debug/') return false;

  res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>eSE/eMule debug log</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:0;background:#111;color:#ddd}
header{padding:8px 14px;background:#1d1d1d;border-bottom:1px solid #333;display:flex;align-items:center;gap:18px}
h1{margin:0;font-size:14px;font-weight:600}
.tabs{display:flex;gap:4px}
.tabs button{background:#222;color:#ddd;border:1px solid #333;padding:4px 12px;cursor:pointer;font-size:12px}
.tabs button.active{background:#0066b3;border-color:#0088dd}
.controls{margin-left:auto;font-size:12px;display:flex;gap:10px;align-items:center}
.controls label{cursor:pointer}
pre{margin:0;padding:10px 14px;height:calc(100vh - 50px);overflow:auto;font-family:Consolas,monospace;font-size:11px;line-height:1.4;white-space:pre;color:#bbb}
pre b{color:#fff}
.hl-RTMP{color:#88c0ff}.hl-CHUNK{color:#9bd96b}.hl-RECV{color:#9bd96b}.hl-MGR{color:#fdd835}
.hl-KAD{color:#ce93d8}.hl-DIAL{color:#ffab40}.hl-HOLE{color:#ff7043}.hl-WARN{color:#ffb74d}.hl-ERR{color:#ef5350}
</style></head><body>
<header>
  <h1>Debug log</h1>
  <div class="tabs">
    <button id="t-emu" class="active" onclick="setSrc('emu')">eMule (C++)</button>
    <button id="t-ese" onclick="setSrc('ese')">eSE (Node)</button>
    <button id="t-both" onclick="setSrc('both')">Both</button>
  </div>
  <div class="controls">
    <label><input type="checkbox" id="auto" checked> auto-refresh 1s</label>
    <button onclick="load()">Refresh</button>
    <span id="status"></span>
  </div>
</header>
<pre id="log">loading...</pre>
<script>
let src='emu', timer=null;
function renderLog(pre,s){
  const tags=/^\\[(RTMP|CHUNK|RECV|MGR|KAD|DIAL|HOLE|WARN|ERR)\\]$/;
  const parts=String(s||'(empty)').split(/(\\[(?:RTMP|CHUNK|RECV|MGR|KAD|DIAL|HOLE|WARN|ERR)\\])/);
  pre.textContent='';
  for(let i=0;i<parts.length;i++){
    const match=parts[i].match(tags);
    if(match){
      const b=document.createElement('b');
      b.className='hl-'+match[1];
      b.textContent=parts[i];
      pre.appendChild(b);
    }else{
      pre.appendChild(document.createTextNode(parts[i]));
    }
  }
}
async function fetchOne(url, label){
  try{
    const r = await fetch(url, {cache:'no-store'});
    const j = await r.json();
    return (j.items||[]).map(l => label?(label+'  '+l):l);
  } catch(e){ return ['(fetch '+url+' failed: '+e.message+')']; }
}
async function load(){
  const st=document.getElementById('status'); st.textContent='loading...';
  let items=[];
  if(src==='emu')  items = await fetchOne('http://localhost:4711/api/live/log?n=200');
  else if(src==='ese') items = await fetchOne('/api/ese/log?n=200');
  else {
    const [e,s] = await Promise.all([
      fetchOne('http://localhost:4711/api/live/log?n=200', '[emu]'),
      fetchOne('/api/ese/log?n=200', '[ese]')]);
    items = e.concat(s).sort();
  }
  const pre=document.getElementById('log');
  renderLog(pre,items.join('\\n'));
  pre.scrollTop = pre.scrollHeight;
  st.textContent = items.length+' lines · '+new Date().toLocaleTimeString();
}
function setSrc(s){
  src=s;
  document.getElementById('t-emu').classList.toggle('active', s==='emu');
  document.getElementById('t-ese').classList.toggle('active', s==='ese');
  document.getElementById('t-both').classList.toggle('active', s==='both');
  load();
}
function startTimer(){ if(timer) clearInterval(timer); if(document.getElementById('auto').checked) timer=setInterval(load,1000); }
document.getElementById('auto').onchange=startTimer;
load(); startTimer();
</script>
</body></html>`);
  return true;
}

module.exports = { handle };
