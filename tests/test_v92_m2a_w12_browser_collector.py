"""Transport-fake E2E for the import-only W12 browser collector."""
from __future__ import annotations
import json
import subprocess
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'tools' / 'architecture' / 'collect_w12_browser_cdp.mjs'
MAX_AUDIT_LINE = 140
def run(script: str) -> str:
    result = subprocess.run(
        ['node', '--input-type=module', '-e', script],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout
class CollectorTests(unittest.TestCase):
    def test_e2e_exact_control_script_and_negatives(self):
        script = r'''
import vm from 'node:vm';
import {createServer} from 'node:http';
import {mkdtemp,readFile,writeFile,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const savedProcess = globalThis.process;
delete globalThis.process;
const m = await import(__MODULE__);
const listen = server => new Promise((ok, no) => {
  server.listen(0, '127.0.0.1', ok);
  server.once('error', no);
});
const stop = server => new Promise(ok => server.close(ok));
const hash = m.sha256;
const A = 'a'.repeat(40);
const runId = 'b'.repeat(64);
const nonce = 'c'.repeat(64);
const canary = 'd'.repeat(64);
const stream = 'e'.repeat(32);
const token = 'f'.repeat(64);
const generation = '1';
const csrf = 'csrf-token';
let loggedOut = false;
let upstreamRequests = 0;
const upstream = createServer((request, response) => {
  const url = new URL(request.url, 'http://x');
  const hardening = {'cache-control':'no-store','referrer-policy':'no-referrer'};
  const send = (status, body = '', headers = {}) => {
    response.writeHead(status, {...hardening, ...headers}).end(body);
  };
  const authorized = (needsCsrf = false) => {
    if (request.headers.referer) return false;
    if (!String(request.headers.cookie).includes('s=1')) return false;
    return !needsCsrf || request.headers['x-csrf-token'] === csrf;
  };
  upstreamRequests += 1;
  if (url.pathname === '/' && url.searchParams.get('w') === 'password') {
    if (url.searchParams.get('p') !== 'p<secret>' || request.headers.referer) return send(400);
    return send(200, 'ok', {'x-csrf-token':csrf,'set-cookie':'s=1; Path=/; HttpOnly'});
  }
  if (url.pathname === '/api/live/broadcast/start') return send(410);
  const needsCsrf = url.pathname === '/api/live/log'
    || url.pathname === '/' && url.searchParams.get('w') === 'logout';
  if (!authorized(needsCsrf)) return send(401);
  if (url.pathname === `/live/${stream}`) {
    return send(200, `<a href="/h/${token}/${generation}/${stream}/stream.m3u8">x`);
  }
  if (url.pathname === `/h/${token}/${generation}/${stream}/stream.m3u8`) {
    return loggedOut ? send(403, 'no') : send(200, '#EXTM3U\nseg_00001.ts\n');
  }
  if (url.pathname === `/h/${token}/${generation}/${stream}/seg_00001.ts`) {
    return request.headers.range === 'bytes=0-15' ? send(206, '0123456789abcdef') : send(200, 'long');
  }
  if (url.pathname === `/h/${canary}/${generation}/${stream}/stream.m3u8`) return send(403, 'no');
  if (url.pathname === '/api/live/log') return send(200, 'clean');
  if (url.pathname === '/' && url.searchParams.get('w') === 'logout') {
    loggedOut = true;
    return send(200, 'ok');
  }
  return send(404, 'x');
});
await listen(upstream);
const baseUrl = `http://127.0.0.1:${upstream.address().port}/`;
const directory = await mkdtemp(join(tmpdir(), 'w12-c-'));
const handoffPath = join(directory, 'browser-handoff.json');
const rawPath = join(directory, 'raw.json');
const donePath = join(directory, 'done.json');
const collector = await readFile(new URL('./tools/architecture/collect_w12_browser_cdp.mjs', import.meta.url), 'utf8');
const candidate = {
  build_commit:A,
  emule_sha256:'1'.repeat(64),
  build_info_sha256:'2'.repeat(64),
  release:'r',
};
const binding = {
  activation_commit:A,
  production_tree_sha256:'3'.repeat(64),
  toolset_sha256:'4'.repeat(64),
  run_id_sha256:hash(runId),
  challenge_nonce_sha256:hash(nonce),
  canary_sha256:hash(canary),
};
const handoff = {
  schema:'ese.v92.w12.browser-handoff/v3',
  A,
  candidate,
  binding,
  base_url:baseUrl,
  login_password:'p<secret>',
  stream_key:stream,
  canary,
  run_id:runId,
  challenge_nonce:nonce,
  raw_path:rawPath,
  done_path:donePath,
};
const handoffText = JSON.stringify(handoff);
await writeFile(handoffPath, handoffText);
const ready = {
  schema:'ese.v92.w12.browser-ready/v3',
  A,
  run_id_sha256:binding.run_id_sha256,
  challenge_nonce_sha256:binding.challenge_nonce_sha256,
  handoff_sha256:hash(handoffText),
  collector_sha256:hash(collector),
};
const readyPath = join(directory, 'browser-ready.json');
await writeFile(readyPath, JSON.stringify(ready));
let controlUrl = '';
let closed = 0;
const tab = {
  async goto(url) {
    controlUrl = url;
    if (new URL(url).search) throw Error('secret URL');
    const html = await (await fetch(url)).text();
    const code = html.match(/<script>([\s\S]*)<\/script>/)[1];
    let cookie = '';
    let resolveComplete;
    let rejectComplete;
    const complete = new Promise((resolve, reject) => {
      resolveComplete = resolve;
      rejectComplete = reject;
    });
    const browserFetch = async (input, options = {}) => {
      const target = new URL(String(input), url);
      const headers = new Headers(options.headers || {});
      if (cookie) headers.set('cookie', cookie);
      const result = await fetch(target, {...options, headers});
      const setCookie = result.headers.get('set-cookie');
      if (setCookie) cookie = setCookie.split(';')[0];
      if (target.pathname === '/__w12/complete') resolveComplete();
      if (target.pathname === '/__w12/fail') rejectComplete(Error('page failed'));
      return result;
    };
    vm.runInNewContext(code, {
      fetch:browserFetch,
      navigator:{product:'Fake',appVersion:'1',userAgent:'Fake/1'},
      URL,
      Headers,
      location:new URL(url),
    });
    await Promise.race([
      complete,
      new Promise((_, reject) => setTimeout(() => reject(Error('page timeout')), 3000)),
    ]);
  },
  async close() { closed += 1; },
};
const browser = {browserId:'fake-browser',tabs:{new:async () => tab}};
const output = await m.collectW12BrowserEvidence({browser,readyPath,timeoutMs:5000});
const raw = JSON.parse(await readFile(rawPath));
const done = JSON.parse(await readFile(donePath));
if (!controlUrl.endsWith('/__w12/control') || controlUrl.includes('secret') || closed !== 1
    || upstreamRequests !== 8 || done.product_sha256 !== hash('Fake')
    || raw.browser.product !== 'Fake' || !raw.events.every(event => event.params)
    || raw.events.some(event => 'path_template' in event)
    || !raw.events.some(event => event.params.request?.headers.cookie)
    || raw.events.filter(event => event.method === 'Network.getResponseBody').length !== 3) {
  throw Error('e2e');
}
m.assertScenario(raw.events, {streamKey:stream,canary});
const multi = structuredClone(raw.events);
const segmentAt = multi.findIndex(event => event.params.request?.url.endsWith('/seg_00001.ts'));
const variantRequest = structuredClone(multi[segmentAt]);
const variantResponse = structuredClone(multi[segmentAt + 1]);
variantRequest.params.requestId = 'variant';
variantRequest.params.request.url = variantRequest.params.request.url.replace('/seg_00001.ts', '/stream_0.m3u8');
delete variantRequest.params.request.headers.range;
variantResponse.params.requestId = 'variant';
variantResponse.params.response.status = 200;
multi.splice(segmentAt, 0, variantRequest, variantResponse);
m.assertScenario(multi, {streamKey:stream,canary});
await access(output.claimPath);
if (!(await readFile(handoffPath))) throw Error('handoff removed');
let reused = false;
try { await m.collectW12BrowserEvidence({browser,readyPath,timeoutMs:1000}); } catch { reused = true; }
if (!reused || closed !== 2) throw Error('claim');
let aborted = false;
let drainTimedOut = false;
const began = Date.now();
try { await m.drainPending(new Set([new Promise(() => {})]), 25, () => { aborted = true; }); }
catch (error) { drainTimedOut = /drain timeout/.test(error.message); }
if (!aborted || !drainTimedOut || Date.now() - began > 500) throw Error('hung upstream drain');
const bad = [];
const reject = (name, action) => {
  try { action(); } catch { bad.push(name); return; }
  throw Error(name);
};
const readyCopy = {...ready};
const requestEvent = (requestId = 'x', url = 'http://127.0.0.1:1/', headers = {}) => ({
  method:'Network.requestWillBeSent',
  params:{requestId,request:{url,method:'GET',headers}},
});
const responseEvent = (requestId = 'x', status = 200) => ({
  method:'Network.responseReceived',
  params:{requestId,response:{status,headers:{}}},
});
const bodyEvent = (body = '', encoded = false) => ({
  method:'Network.getResponseBody',
  params:{requestId:'x',body,base64Encoded:encoded},
});
reject('duplicate', () => m.parseStrictJson('{"x":1,"x":2}'));
reject('size', () => m.parseStrictJson(' '.repeat(200000)));
reject('ready-A', () => m.validateReadyV3({...readyCopy,A:'a'}));
reject('ready-schema', () => m.validateReadyV3({...readyCopy,schema:'x'}));
reject('candidate', () => m.validateHandoffV3({...handoff,candidate:{}}));
reject('binding', () => m.validateHandoffV3({...handoff,binding:{}}));
reject('binding-link', () => m.assertReadyHandoffBinding(
  readyCopy, {...handoff,A:'0'.repeat(40)},
));
reject('loopback', () => m.assertLoopbackUrl('http://localhost:1/'));
reject('loopback-query', () => m.assertLoopbackUrl('http://127.0.0.1:1/?x=1'));
reject('cap-token', () => m.assertCapabilityPath(`/h/x/1/${stream}/stream.m3u8`, stream));
reject('cap-gen', () => m.assertCapabilityPath(`/h/${token}/0/${stream}/stream.m3u8`, stream));
reject('cap-stream', () => m.assertCapabilityPath(
  `/h/${token}/1/${'0'.repeat(32)}/stream.m3u8`, stream,
));
reject('request-shape', () => m.assertEventOrder([requestEvent('x', 'http://example/')]));
reject('cross-id', () => m.assertEventOrder([responseEvent()]));
reject('duplicate-request', () => m.assertEventOrder([requestEvent(), requestEvent()]));
reject('duplicate-response', () => m.assertEventOrder([
  requestEvent(), responseEvent(), responseEvent(),
]));
reject('body-before', () => m.assertEventOrder([requestEvent(), bodyEvent()]));
reject('body-size', () => m.assertEventOrder([
  requestEvent(), responseEvent(), bodyEvent('x'.repeat(50000)),
]));
reject('body-base64', () => m.assertEventOrder([
  requestEvent(), responseEvent(), bodyEvent('x', true),
]));
reject('status', () => m.assertEventOrder([requestEvent(), responseEvent('x', '200')]));
reject('scenario-broadcast', () => m.assertScenario([
  requestEvent('x', 'http://127.0.0.1:1/api/live/broadcast/start'), responseEvent(),
], {streamKey:stream,canary}));
reject('scenario-referer', () => m.assertScenario([
  requestEvent('x', 'http://127.0.0.1:1/', {referer:'x'}), responseEvent(),
], {streamKey:stream,canary}));
reject('done', () => m.validateDoneV3({}, raw, readyCopy, 'x'));
reject('nonhex', () => m.validateReadyV3({...readyCopy,handoff_sha256:'Z'.repeat(64)}));
reject('extra', () => m.validateReadyV3({...readyCopy,x:1}));
try { await m.atomicCreateJson(rawPath, {x:1}); throw Error('overwrite'); }
catch (error) { if (error.message === 'overwrite') throw error; bad.push('raw-overwrite'); }
if (bad.length < 25) throw Error(`negatives ${bad.length}`);
await stop(upstream);
globalThis.process = savedProcess;
console.log(`PASS ${bad.length}`);
'''.replace('__MODULE__', json.dumps(MODULE.as_uri()))
        self.assertTrue(run(script).startswith('PASS '))
    def test_no_cli_hardening_markers_and_line_lengths(self):
        surfaces = [
            ROOT / 'tools' / 'architecture' / 'collect_w12_browser_cdp.mjs',
            ROOT / 'tests' / 'test_v92_m2a_w12_browser_collector.py',
        ]
        for surface in surfaces:
            violations = [
                (number, len(line))
                for number, line in enumerate(surface.read_text(encoding='utf-8').splitlines(), 1)
                if len(line) > MAX_AUDIT_LINE
            ]
            self.assertFalse(violations, f'{surface.name} over {MAX_AUDIT_LINE}: {violations[:3]}')
        source = MODULE.read_text(encoding='utf-8')
        markers = (
            'collectW12BrowserEvidence',
            "server.listen(0, '127.0.0.1'",
            'response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers)',
            'drainPending(drains',
            'server.closeAllConnections',
            'capability[1] === config.canary',
            '<link rel="icon" href="data:,">',
            "local.pathname === '/favicon.ico'",
        )
        for marker in markers:
            self.assertIn(marker, source)
        self.assertNotIn('process.argv', source)
        self.assertNotIn('/__w12/control?p=', source)
        checked = subprocess.run(['node', '--check', str(MODULE)], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
if __name__ == '__main__':
    unittest.main()
