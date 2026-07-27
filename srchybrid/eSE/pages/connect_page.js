'use strict';

function init() {}

function handle(url, req, res) {
  if (url.pathname !== '/connect' && !url.pathname.startsWith('/pair/')) {
    return false;
  }
  res.writeHead(410, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify({
    error: 'gone',
    reason: 'remote_access_postponed'
  }));
  return true;
}

module.exports = { init, handle };
