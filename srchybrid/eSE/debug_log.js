// eSE — In-process debug log ring buffer
// Mirrors the C++ CLiveDebugLog so the dashboard can show eMule and eSE
// events side-by-side. Hooks console.log/warn/error so existing log
// statements get captured without rewriting them. Exposed at
// GET /api/ese/log -> {"items":[...]}.
//
// Capacity 500 lines, oldest dropped on overflow. No persistence.

const MAX_LINES = 500;
const lines = [];

function pad2(n) { return n < 10 ? '0' + n : '' + n; }

function ts() {
  const d = new Date();
  return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

function append(tag, args) {
  const body = args.map(a => {
    if (a instanceof Error) return a.stack || a.message;
    if (typeof a === 'object') {
      try { return JSON.stringify(a); } catch (e) { return String(a); }
    }
    return String(a);
  }).join(' ');
  // One ring-buffer entry per call: strip newlines/ANSI escapes so user- or
  // peer-controlled text can't forge extra log lines in the dashboard.
  const clean = body.replace(/[\r\n\x1b]+/g, ' ');
  const line = ts() + ' [' + tag + '] ' + clean;
  lines.push(line);
  while (lines.length > MAX_LINES) lines.shift();
}

// Hook console.log/warn/error so any pre-existing log call is captured.
// The original implementations still write to stdout/stderr — we just
// also push the formatted line into our ring buffer.
const orig = {
  log:   console.log,
  warn:  console.warn,
  error: console.error,
  info:  console.info,
};

function install() {
  // Sanitize string args (strip CR/LF/ANSI) for BOTH the ring buffer AND stdout, so peer- or
  // user-controlled text can never forge log lines (CodeQL js/log-injection). Error objects
  // pass through untouched so developer stack traces keep their newlines.
  const san = (a) => {
    const out = [];
    for (let i = 0; i < a.length; i++)
      out.push(typeof a[i] === 'string' ? a[i].replace(/[\r\n\x1b]+/g, ' ') : a[i]);
    return out;
  };
  console.log   = function () { const a = san(arguments); append('LOG',  a); orig.log.apply(console, a); };
  console.info  = function () { const a = san(arguments); append('LOG',  a); orig.info.apply(console, a); };
  console.warn  = function () { const a = san(arguments); append('WARN', a); orig.warn.apply(console, a); };
  console.error = function () { const a = san(arguments); append('ERR',  a); orig.error.apply(console, a); };

  // Capture any uncaught errors that escaped the existing handlers.
  process.on('uncaughtException',  err => append('UNCAUGHT',  [err]));
  process.on('unhandledRejection', err => append('UNHANDLED', [err]));
}

// Manual emit (when you don't want it on stdout).
function add(tag, msg) { append(tag, [msg]); }

function recent(n) {
  if (!n || n <= 0) n = 100;
  if (n > MAX_LINES) n = MAX_LINES;
  return lines.slice(-n);
}

function handle(url, req, res) {
  if (url.pathname === '/api/ese/log') {
    const n = parseInt(url.searchParams.get('n') || '100', 10);
    const items = recent(n);
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(JSON.stringify({ items }));
    return true;
  }
  return false;
}

module.exports = { install, add, recent, handle };
