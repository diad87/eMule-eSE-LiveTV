'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const hash = 'a'.repeat(32);
const localPlayer = require('../live_player_html');
const security = require('../security');

function api() {
  const requests = [], module = { exports: {} };
  const dirname = path.join(__dirname, '../eSE-live');
  vm.runInNewContext(fs.readFileSync(path.join(dirname, 'channel_api.js'), 'utf8'), {
    module, __dirname: dirname, process: { env: { ESE_TEST_MODE: '1' } }, console, setInterval() {}, clearInterval() {},
    require(name) {
      if(name === 'path' || name === 'os')return require(name);
      if(name === 'fs')return { existsSync: () => true };
      if(name === '../live_player_html')return localPlayer;
      if(name === './live_watch_page')return require('../eSE-live/live_watch_page');
      if(name === './nodes_bootstrap')return { startFromEnv: () => Promise.resolve({ status: 'disabled' }) };
      if(name === 'http')return { get(url, options, callback) {
        requests.push(url);
        const response = new EventEmitter();
        const request = new EventEmitter();request.destroy=()=>{};
        if(callback && url.includes('/api/live/join?'))queueMicrotask(()=>{callback(response);response.emit('data','{"success":true}');response.emit('end');});
        return request;
      } };
      return {};
    }
  });
  requests.length=0;
  return {
    requests,
    route(route, method='GET') {
      const res={headers:{},writeHead(status,headers={}){this.status=status;Object.assign(this.headers,headers);},setHeader(k,v){this.headers[k]=v;},end(body){this.body=body;}};
      assert.equal(module.exports.handleRoute(new URL(route,'http://fixture'),{method},res,{}),true);
      return res;
    }
  };
}
test('GET watch only renders: no join, and API join requires POST without changing native wire method', async () => {
  const server=api();
  const page=server.route('/live/watch/'+hash);
  assert.equal(page.status,200);assert.equal(server.requests.length,0);
  for(const m of page.body.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))new vm.Script(m[1]);
  const rejected=server.route('/api/live/join?key='+hash);
  assert.equal(rejected.status,405);assert.equal(server.requests.length,0);
  const accepted=server.route('/api/live/join?key='+hash,'POST');
  await new Promise(setImmediate);
  assert.equal(accepted.status,200);
  assert.equal(server.requests.length,1);
  assert.match(server.requests[0],/127\.0\.0\.1:4711\/api\/live\/join\?key=/);
});
test('all local/remote player scripts compile and malformed keys never touch backend', () => {
  const server=api();
  for(const route of ['/live/watch/local','/live/watch/local_fixture','/live/watch/'+hash]) {
    const page=server.route(route);
    assert.equal(page.status,200);
    for(const m of page.body.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))new vm.Script(m[1]);
  }
  assert.equal(server.route('/live/watch/not-a-hash').status,400);
  assert.equal(server.requests.length,0);
});
async function browser(status=200) {
  const html=api().route('/live/watch/'+hash).body;
  const nodes={},requests=[],events={},timers=[],beacons=[];
  for(const id of ['v','cinema','join-overlay','join-spinner','join-state','join-detail','join-start','join-retry','jo-peers','jo-chunks','jo-kad','time','play-btn','mute-btn','ch-title','audioSel'])nodes[id]={
    handlers:{},style:{},hidden:false,paused:true,currentTime:0,muted:true,src:'',attributes:{},classList:{add(){},remove(){}},
    addEventListener(event,fn){this.handlers[event]=fn;},setAttribute(k,v){this.attributes[k]=v;},focus(){},canPlayType(){return 'probably';},play(){this.paused=false;return Promise.resolve();},pause(){this.paused=true;}
  };
  const context=vm.createContext({
    document:{getElementById:id=>nodes[id],fullscreenElement:null},console,AbortController,
    setTimeout(fn){timers.push(fn);return timers.length;},clearTimeout(){},setInterval(fn){timers.push(fn);return timers.length;},clearInterval(){},
    addEventListener:(event,fn)=>events[event]=fn,
    navigator:{sendBeacon:url=>{beacons.push(url);return true;}},
    fetch(url,options={}){requests.push({url,options});return Promise.resolve({ok:status===200,status,json:()=>Promise.resolve(url.includes('/join?')?{success:true}:url.includes('/debug')?{peers:{viewPeers:0},chunks:{count:0}}:{channels:[]})});}
  });
  context.window=context;
  for(const m of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))vm.runInContext(m[1],context);
  await new Promise(setImmediate);
  return {nodes,requests,events,beacons,timers,context};
}
test('rendering/preloading does not join, load HLS or leave; explicit button starts one POST and HLS', async () => {
  const untouched=await browser();
  assert.equal(untouched.requests.some(r=>r.url.includes('/join?')),false);
  assert.equal(untouched.nodes.v.src,'');
  untouched.events.pagehide();assert.equal(untouched.beacons.length,0);

  const ui=await browser();
  ui.nodes['join-start'].handlers.click.call(ui.nodes['join-start']);
  await new Promise(setImmediate);
  const joins=ui.requests.filter(r=>r.url.includes('/join?'));
  assert.equal(joins.length,1);assert.equal(joins[0].options.method,'POST');
  assert.equal(ui.nodes.v.src,'/hls-local/'+hash+'/stream.m3u8');
  ui.nodes.v.handlers.playing();
  assert.equal(vm.runInContext('joinState',ui.context),'PLAYING');
  ui.nodes.v.paused=false;
  ui.context.togglePlay();assert.equal(ui.nodes.v.paused,true);
  ui.events.pagehide();assert.equal(ui.beacons.length,1);
});
test('unauthorized or failed join offers retry and never starts media', async () => {
  const ui=await browser(401);
  ui.nodes['join-start'].handlers.click.call(ui.nodes['join-start']);
  await new Promise(setImmediate);
  assert.equal(ui.nodes.v.src,'');
  assert.equal(ui.nodes['join-start'].hidden,false);
  assert.equal(ui.nodes['join-start'].disabled,false);
  assert.match(ui.nodes['join-detail'].textContent,/Vincula/);
});
test('join still passes the API authentication and cross-site boundary', () => {
  security.init({tunnel:{CONFIG:{accessToken:'fixture_token_for_test_only'}}});
  for(const headers of [{host:'192.168.1.5:8080'},{host:'192.168.1.5:8080',origin:'https://other.example','x-ese-token':'fixture_token_for_test_only'}]){
    let status;
    const allowed=security.apply(new URL('/api/live/join?key='+hash,'http://192.168.1.5:8080'),{method:'POST',socket:{remoteAddress:'192.168.1.10'},headers},{writeHead(value){status=value},end(){}});
    assert.equal(allowed,false);assert.ok(status===401||status===403);
  }
});

