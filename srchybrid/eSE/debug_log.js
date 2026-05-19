// eSE — In-process debug log ring buffer + on-disk persistence.
// Mirrors the C++ CLiveDebugLog so the dashboard can show eMule and eSE
// events side-by-side. Hooks console.log/warn/error so existing log
// statements get captured without rewriting them.
//
// Exposed at:
//   GET /debug              → human-readable HTML viewer (auto-refresh + copy + download .txt)
//   GET /api/ese/log        → JSON {"items":[...]}
//   GET /api/ese/log/raw    → text/plain dump of the in-memory ring buffer
//   GET /api/ese/log/file   → text/plain dump of the on-disk debug.log (+ debug.log.1 if rotated)
//
// Capacity 500 lines in memory, oldest dropped on overflow. Also appended to
// %APPDATA%\eSE\debug.log (pkg mode) or alongside the script (dev mode);
// rotates to .log.1 when it crosses 1 MB. Worst case ~2 MB on disk.

const fs   = require('fs');
const path = require('path');

const MAX_LINES = 500;
const MAX_FILE_BYTES = 1 * 1024 * 1024;   // 1 MB
const lines = [];

let _logFile = null;
function getLogFile() {
  if (_logFile) return _logFile;
  try {
    const runtimeDir = require('./runtime_dir');
    _logFile = runtimeDir.join('debug.log');
  } catch (e) {
    _logFile = path.join(__dirname, 'debug.log');
  }
  return _logFile;
}

function pad2(n) { return n < 10 ? '0' + n : '' + n; }

function ts() {
  const d = new Date();
  return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate())
       + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

// v8.0.7: strip CR/LF/TAB so a user-controlled value can't forge extra
// ring-buffer entries (CodeQL js/log-injection #58-67).
function safe(value) {
  return String(value == null ? '' : value).replace(/[\r\n\t]+/g, ' ');
}

function _appendToFile(line) {
  // Best-effort; failures are swallowed because the in-memory buffer is the
  // primary surface and we never want logging to crash the app.
  try {
    const f = getLogFile();
    try {
      const st = fs.statSync(f);
      if (st && st.size > MAX_FILE_BYTES) {
        try { fs.renameSync(f, f + '.1'); } catch (e) {}
      }
    } catch (e) { /* not yet created — fine */ }
    fs.appendFileSync(f, line + '\r\n');
  } catch (e) { /* disk full / permission denied — silent */ }
}

function append(tag, args) {
  const body = args.map(a => {
    if (a instanceof Error) return safe(a.stack || a.message);
    if (typeof a === 'object') {
      try { return safe(JSON.stringify(a)); } catch (e) { return safe(a); }
    }
    return safe(a);
  }).join(' ');
  const line = ts() + ' [' + tag + '] ' + body;
  lines.push(line);
  while (lines.length > MAX_LINES) lines.shift();
  _appendToFile(line);
}

// Hook console.log/warn/error so any pre-existing log call is captured.
// The original implementations still write to stdout/stderr — we just
// also push the formatted line into our ring buffer + the on-disk file.
const orig = {
  log:   console.log,
  warn:  console.warn,
  error: console.error,
  info:  console.info,
};

function install() {
  console.log   = function () { append('LOG',  Array.from(arguments)); orig.log.apply(console, arguments); };
  console.info  = function () { append('LOG',  Array.from(arguments)); orig.info.apply(console, arguments); };
  console.warn  = function () { append('WARN', Array.from(arguments)); orig.warn.apply(console, arguments); };
  console.error = function () { append('ERR',  Array.from(arguments)); orig.error.apply(console, arguments); };

  process.on('uncaughtException',  err => append('UNCAUGHT',  [err]));
  process.on('unhandledRejection', err => append('UNHANDLED', [err]));

  // Emit a session boundary so it's clear in the on-disk log where each
  // ese-server launch begins. Two blank lines + a banner.
  try {
    _appendToFile('');
    _appendToFile('');
    _appendToFile('=== eSE session start @ ' + ts() + ' (pid=' + process.pid + ') ===');
  } catch (e) {}
}

function add(tag, msg) { append(tag, [msg]); }

function recent(n) {
  if (!n || n <= 0) n = 100;
  if (n > MAX_LINES) n = MAX_LINES;
  return lines.slice(-n);
}

function _readLogFile() {
  // Concatenates rotated chunk (.log.1) + current chunk (.log) so the user
  // gets one continuous transcript when they download the file.
  const f = getLogFile();
  let buf = '';
  try { buf += fs.readFileSync(f + '.1', 'utf8'); } catch (e) {}
  try { buf += fs.readFileSync(f,        'utf8'); } catch (e) {}
  return buf;
}

function _viewerHtml() {
  // Self-contained HTML viewer. Polls /api/ese/log/raw every 2 s. Buttons:
  //   - Copy all   → clipboard
  //   - Download   → .txt file with the entire on-disk log
  //   - Pause      → stop auto-refresh
  return '<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">'
    + '<title>eSE — debug log</title>'
    + '<link rel="icon" href="/emule_mascot.svg" />'
    + '<style>'
    + '*{box-sizing:border-box}html,body{height:100%;margin:0}'
    + 'body{background:#0a0a0f;color:#e5e5e5;font-family:system-ui,-apple-system,Segoe UI,sans-serif;display:flex;flex-direction:column}'
    + 'header{display:flex;align-items:center;gap:8px;padding:10px 14px;background:#16161e;border-bottom:1px solid #222}'
    + 'header h1{margin:0;font-size:15px;color:#ff6b35;font-weight:700;flex:1}'
    + 'button{background:#1f1f28;border:1px solid #333;color:#e5e5e5;padding:6px 12px;border-radius:6px;cursor:pointer;font-size:12px}'
    + 'button:hover{background:#2a2a35;color:#fff}'
    + 'button.active{background:#ff6b35;border-color:#ff6b35;color:#fff}'
    + '#status{font-size:11px;color:#888;margin-left:8px}'
    + 'pre{margin:0;padding:14px;font-family:Consolas,Menlo,monospace;font-size:12px;color:#b8b8b8;flex:1;overflow:auto;white-space:pre-wrap;word-break:break-all;line-height:1.45}'
    + 'pre .err{color:#e74c3c}pre .warn{color:#f1c40f}pre .uncaught{color:#e74c3c;font-weight:600}'
    + '</style></head><body>'
    + '<header>'
    + '<h1>eSE debug log</h1>'
    + '<button id="copy">Copiar todo</button>'
    + '<button onclick="location.href=\'/api/ese/log/file\'">Descargar .txt</button>'
    + '<button id="pause">Pausar</button>'
    + '<span id="status">cargando...</span>'
    + '</header>'
    + '<pre id="log">Cargando...</pre>'
    + '<script>'
    + '(function(){'
    + 'var pre=document.getElementById("log");var st=document.getElementById("status");'
    + 'var paused=false;var pauseBtn=document.getElementById("pause");'
    + 'function colorize(text){return text'
    +   '.replace(/\\[ERR\\]([^\\n]*)/g,"<span class=\\"err\\">[ERR]$1</span>")'
    +   '.replace(/\\[WARN\\]([^\\n]*)/g,"<span class=\\"warn\\">[WARN]$1</span>")'
    +   '.replace(/\\[UNCAUGHT\\]([^\\n]*)/g,"<span class=\\"uncaught\\">[UNCAUGHT]$1</span>")'
    +   '.replace(/\\[UNHANDLED\\]([^\\n]*)/g,"<span class=\\"uncaught\\">[UNHANDLED]$1</span>");'
    + '}'
    + 'function refresh(){'
    +   'if(paused)return;'
    +   'fetch("/api/ese/log/raw?n=500",{cache:"no-store"})'
    +     '.then(function(r){return r.text();})'
    +     '.then(function(t){'
    +       'var atBottom=(pre.scrollTop+pre.clientHeight)>=(pre.scrollHeight-30);'
    +       'pre.innerHTML=colorize(t||"(vacio)");'
    +       'if(atBottom)pre.scrollTop=pre.scrollHeight;'
    +       'var d=new Date();st.textContent="actualizado "+d.toLocaleTimeString();'
    +     '})'
    +     '.catch(function(){st.textContent="error de conexion";});'
    + '}'
    + 'document.getElementById("copy").addEventListener("click",function(){'
    +   'fetch("/api/ese/log/raw?n=500",{cache:"no-store"}).then(function(r){return r.text();}).then(function(t){'
    +     'if(navigator.clipboard&&navigator.clipboard.writeText){'
    +       'navigator.clipboard.writeText(t).then(function(){st.textContent="copiado al portapapeles ("+t.length+" chars)";});'
    +     '}else{'
    +       'var ta=document.createElement("textarea");ta.value=t;document.body.appendChild(ta);ta.select();'
    +       'try{document.execCommand("copy");st.textContent="copiado al portapapeles";}catch(e){}'
    +       'document.body.removeChild(ta);'
    +     '}'
    +   '});'
    + '});'
    + 'pauseBtn.addEventListener("click",function(){'
    +   'paused=!paused;pauseBtn.textContent=paused?"Reanudar":"Pausar";'
    +   'pauseBtn.className=paused?"active":"";'
    + '});'
    + 'refresh();setInterval(refresh,2000);'
    + '})();'
    + '</script></body></html>';
}

function handle(url, req, res) {
  if (url.pathname === '/debug') {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(_viewerHtml());
    return true;
  }
  if (url.pathname === '/api/ese/log') {
    const n = parseInt(url.searchParams.get('n') || '100', 10);
    const items = recent(n);
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    });
    res.end(JSON.stringify({ items }));
    return true;
  }
  if (url.pathname === '/api/ese/log/raw') {
    // Plain-text dump of the ring buffer for the /debug viewer + curl users.
    const n = parseInt(url.searchParams.get('n') || '500', 10);
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(recent(n).join('\r\n'));
    return true;
  }
  if (url.pathname === '/api/ese/log/file') {
    // Full on-disk transcript (current + rotated chunk), Content-Disposition
    // so the browser saves as ese-debug.txt instead of opening inline.
    const body = _readLogFile();
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Disposition': 'attachment; filename="ese-debug.txt"',
    });
    res.end(body);
    return true;
  }
  return false;
}

module.exports = { install, add, recent, handle, safe, getLogFile };
