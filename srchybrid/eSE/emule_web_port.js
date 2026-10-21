'use strict';
const fs = require('fs');
const path = require('path');
function validPort(value) {
  const text = String(value).trim();
  if (!/^\d{1,5}$/.test(text) || Number(text) < 1 || Number(text) > 65535) {
    throw new Error('Invalid eMule WebUI port');
  }
  return Number(text);
}
function resolveWebPort(env = process.env) {
  if (env.ESE_EMULE_WEB_PORT !== undefined) return validPort(env.ESE_EMULE_WEB_PORT);
  if (env.ESE_EMULE_CONFIG_DIR) {
    const bytes = fs.readFileSync(path.join(env.ESE_EMULE_CONFIG_DIR, 'preferences.ini'));
    // Windows profile APIs also accept UTF-16LE INI files with a BOM.
    const unicode = bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe;
    if (unicode && (bytes.length & 1)) throw new Error('Invalid eMule WebUI configuration encoding');
    const ini = unicode ? bytes.subarray(2).toString('utf16le') : bytes.toString('utf8');
    let web = false;
    for (const line of ini.replace(/^\uFEFF/, '').split(/\r?\n/)) {
      const section = /^\s*\[([^\]]+)\]\s*$/.exec(line);
      if (section) { web = section[1].toLowerCase() === 'webserver'; continue; }
      const port = /^\s*Port\s*=\s*([^;#]*)/i.exec(line);
      if (web && port) return validPort(port[1]);
    }
  }
  // Official WebUI default only when no explicit port was configured.
  return 4711;
}
module.exports = { resolveWebPort, validPort };
