#include "WebLiveApiLegacyController.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>

namespace eSELive {
WebLiveApiLegacyController::WebLiveApiLegacyController(const M2AParentPort& parent) noexcept : m_parent(parent) {}
M2AModuleHandle M2A_BIND_W11_55908BF94D(const M2AParentPort& parent) { return parent ? MakeM2AModuleHandle(new WebLiveApiLegacyController(parent)) : M2AModuleHandle(); }
void M2A_UNBIND_W11_55908BF94D(const M2AParentPort&) {}
} // namespace eSELive

namespace ese { namespace web { namespace {
bool SafeLeaf(const std::string& value) {
	if (value.empty() || value.size() >= 64 || value.find("..") != std::string::npos) return false;
	for (unsigned char c : value) if (!(std::isalnum(c) || c == '_' || c == '-' || c == '.')) return false;
	std::string lower(value); std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return lower.size() >= 3 && (lower.compare(lower.size() - 3, 3, ".ts") == 0 || (lower.size() >= 5 && lower.compare(lower.size() - 5, 5, ".m3u8") == 0));
}
bool HexKey16(const std::string& value) { if (value.size() != 32) return false; for (unsigned char c : value) if (!std::isxdigit(c)) return false; return true; }
std::string PageHeader(const std::string& body, bool dashboard) {
	std::string value = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ";
	value += std::to_string(body.size());
	if (dashboard) value += "\r\nCache-Control: no-cache";
	return value + "\r\n\r\n";
}
bool Hls(const W11LegacyRequest& request, const W11LegacyPort& port, W11LegacyResponse& response) {
	if (port.resolve_hls == nullptr) return false;
	W11HlsSnapshot snapshot;
	if (!port.resolve_hls(port.context, request, snapshot)) return false;
	const bool fallback = !snapshot.root_exists && !snapshot.viewer_key.empty();
	response.file_response = true; response.hls = true; response.cors_wildcard = true; response.cors_origin = "*";
	response.maximum_bytes = 20ull * 1024ull * 1024ull;
	response.file_path = snapshot.root_path + (fallback ? "\\" + snapshot.viewer_key : "") + "\\" + request.resource;
	response.file_name = request.resource; response.public_path = request.resource; response.file_range = request.range;
	response.concurrent = true; response.allow_empty = false;
	if (fallback && port.note_player_fetch) port.note_player_fetch(port.context);
	return true;
}
static const char* DashboardHtml() { return
"<!DOCTYPE html><html lang=es><head><meta charset=utf-8><title>eSE Live (mini)</title>"
"<style>body{background:#0a0a0e;color:#e2e8f0;font-family:system-ui;margin:0;padding:20px;max-width:900px;margin:auto}"
"h1{color:#fff}.box{background:#13141a;border:1px solid #2a2a2e;border-radius:8px;padding:16px;margin:14px 0}"
"button{background:#4f46e5;color:#fff;border:0;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:700;font-size:13px}"
"button.stop{background:#dc2626}button.warn{background:#f59e0b}"
"input{background:#0e0e10;border:1px solid #2a2a2e;color:#ddd;padding:8px;border-radius:5px;font-family:monospace;font-size:12px}"
"input.wide{width:100%}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}"
".pf{display:flex;gap:14px;flex-wrap:wrap;font-size:13px}.pf>div{padding:4px 0}"
".ok{color:#10b981}.err{color:#ef4444}.warn-c{color:#f59e0b}"
"a{color:#818cf8}code{background:#0e0e10;padding:2px 6px;border-radius:3px;font-size:90%}"
"#log{font-family:monospace;font-size:11px;color:#94a3b8;background:#0e0e10;padding:8px;border-radius:5px;max-height:140px;overflow-y:auto;white-space:pre-wrap}"
"</style></head><body>"
"<h1>🎬 eSE Live <span style=font-size:13px;color:#6b7280>mini dashboard (sin Node.js)</span></h1>"
"<p style=font-size:13px;color:#9ca3af>Esta es la versión embebida en <code>emule.exe</code>. Para la experiencia completa abre <a href=http://localhost:8080/live>http://localhost:8080/live</a> (requiere ese-server.exe).</p>"
"<div class=box><h3 style=margin-top:0>🔍 Pre-flight</h3><div class=pf id=pf>cargando...</div></div>"
"<div class=box><h3 style=margin-top:0>NetLab beta</h3><div id=nl-state style=font-size:12px;color:#94a3b8>cargando...</div>"
"<div class=row><button id=nl-toggle class=warn>Desactivar todo</button><button id=nl-copy>Copiar informe saneado</button></div></div>"
"<div class=box><h3 style=margin-top:0>🎬 Emisión</h3>"
"<div class=row><label>Título: <input id=br-title placeholder='Mi Stream' value='eSE Demo'></label>"
"<select id=br-source style=padding:8px;background:#0e0e10;color:#ddd;border:1px solid #2a2a2e;border-radius:5px>"
"<option value=testpattern>Test Pattern</option><option value=screen>Screen Capture</option><option value=rtmp>OBS (RTMP)</option></select>"
"<select id=br-bitrate style=padding:8px;background:#0e0e10;color:#ddd;border:1px solid #2a2a2e;border-radius:5px>"
"<option>1500</option><option selected>3000</option><option>5000</option></select>"
"<button id=br-start>▶ START</button><button id=br-stop class=stop>■ STOP</button></div>"
"<div id=br-status style=font-size:12px;color:#94a3b8;margin-top:8px>Inactivo.</div>"
"<div id=br-link style=margin-top:8px;display:none><b>Link:</b> <input id=br-link-input class=wide readonly></div>"
"</div>"
"<div class=box><h3 style=margin-top:0>👁 Ver stream</h3>"
"<div class=row><input id=join-link class=wide placeholder='ed2k://|live|HEX|IP:PUERTO|TITULO|/'><button id=join-btn>Conectar</button></div>"
"<div id=join-msg style=font-size:12px;color:#94a3b8;margin-top:8px></div>"
"<div class=row><a href=/hls/stream.m3u8 style=font-size:12px>📺 Abrir HLS directo (VLC)</a></div>"
"</div>"
"<div class=box><h3 style=margin-top:0>📊 Estado en vivo</h3><div id=mon style=font-size:12px;font-family:monospace>—</div></div>"
"<div class=box><h3 style=margin-top:0>📜 Log</h3><div id=log></div></div>"
"<p style=text-align:center;margin-top:24px;font-size:11px;color:#6b7280>"
"<a href=/api/status>/api/status</a> · <a href=/api/live/debug>/api/live/debug</a> · <a href=/api/live/preflight>/api/live/preflight</a>"
"</p>"
"<script>"
"function L(t){var l=document.getElementById('log');l.textContent+=new Date().toLocaleTimeString()+' '+t+'\\n';l.scrollTop=l.scrollHeight;}"
"function PF(){fetch('/api/live/preflight').then(function(r){return r.json();}).then(function(d){var p=document.getElementById('pf');var f=function(ok,t){var c=ok===true?'ok':(ok==='checking'?'warn-c':'err');var i=ok===true?'✅':(ok==='checking'?'⏳':'❌');return '<div class='+c+'>'+i+' '+t+'</div>';};p.innerHTML=f(d.kad_connected,'Kad')+f(d.high_id?true:(d.firewall_checking?'checking':false),d.high_id?'HighID':(d.firewall_checking?'NAT…':'LowID'))+f(d.ffmpeg_found,'FFmpeg')+f(!!d.public_ip,'IP '+(d.public_ip||'?')+':'+d.port);}).catch(function(){});}"
"function MON(){fetch('/api/live/debug').then(function(r){return r.json();}).then(function(d){var m=document.getElementById('mon');if(!d){m.textContent='-';return;}m.innerHTML='broadcasting='+d.broadcasting+' viewing='+d.viewing+'<br>buffer='+(d.chunks?d.chunks.count+' segs ['+d.chunks.oldestSeq+'..'+d.chunks.newestSeq+']':'')+'<br>peers: view='+(d.peers?d.peers.viewPeers:0)+' broadcast='+(d.peers?d.peers.broadcastPeers:0)+' mesh='+(d.peers?d.peers.meshPeers:0)+'<br>kad: '+(d.discovery?'connected='+d.discovery.kadConnected+' streams='+d.discovery.knownStreams:'?');}).catch(function(){});}"
"function NL(){fetch('/api/ese/v9').then(function(r){return r.json();}).then(function(d){var n=d.netlab||{};var i=n.independent||{};var s=document.getElementById('nl-state');s.dataset.on=n.enabled?'1':'0';s.textContent='Laboratorio: '+(n.enabled?'ACTIVO':'OFF')+' | base '+(n.consent||'?')+' | avanzado '+(n.advanced_consent||'?')+' | contribucion '+(n.contribution_consent||'?')+' | Punch3 '+((n.staged||{}).ed2k_punch3?'ON':'OFF')+' | KRP '+(i.krp?'ON':'OFF')+' | Kad6 Beta Exit '+(i.kad6_beta_exit?'ON':'OFF');var b=document.getElementById('nl-toggle');b.disabled=n.consent!=='accepted';b.textContent=n.enabled?'Desactivar todo':'Reactivar niveles aceptados';b.className=n.enabled?'stop':'warn';}).catch(function(){});}"
"PF();MON();NL();setInterval(PF,8000);setInterval(MON,2000);setInterval(NL,5000);"
"document.getElementById('nl-toggle').onclick=function(){var on=document.getElementById('nl-state').dataset.on==='1'?'0':'1';fetch('/api/ese/v9?on='+on).then(function(){NL();});};"
"document.getElementById('nl-copy').onclick=function(){fetch('/api/ese/netlab/report').then(function(r){return r.text();}).then(function(t){if(navigator.clipboard&&navigator.clipboard.writeText){return navigator.clipboard.writeText(t);}var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();}).then(function(){L('Informe NetLab saneado copiado');}).catch(function(){L('No se pudo copiar el informe');});};"
"document.getElementById('br-start').onclick=function(){var t=encodeURIComponent(document.getElementById('br-title').value||'eSE');var s=document.getElementById('br-source').value;var b=document.getElementById('br-bitrate').value;L('Iniciando broadcast '+s+' '+b+'k…');fetch('/api/live/broadcast/start?source='+s+'&title='+t+'&bitrate='+b).then(function(r){return r.json();}).then(function(d){if(d.success){document.getElementById('br-status').textContent='✅ Emitiendo: '+d.source+' @ '+d.bitrate+' kbps';if(d.link){document.getElementById('br-link').style.display='';document.getElementById('br-link-input').value=d.link;}L('OK link='+d.link);}else{document.getElementById('br-status').textContent='❌ '+(d.error||'fallo');L('FAIL '+d.error);}});};"
"document.getElementById('br-stop').onclick=function(){fetch('/api/live/broadcast/stop').then(function(r){return r.json();}).then(function(d){document.getElementById('br-status').textContent='Detenido';document.getElementById('br-link').style.display='none';L('Stopped');});};"
"document.getElementById('join-btn').onclick=function(){var l=document.getElementById('join-link').value.trim();if(!l){return;}L('Joining '+l);fetch('/api/live/direct_join?link='+encodeURIComponent(l)).then(function(r){return r.json();}).then(function(d){var m=document.getElementById('join-msg');if(d.success){m.innerHTML='✅ Conectado a '+d.ip+':'+d.port+'. <a href=/hls/stream.m3u8>Abre el HLS</a>';m.className='ok';L('Joined');}else{m.textContent='❌ '+(d.error||'fallo');m.className='err';}});};"
"</script></body></html>";
}
static const char* LiveIndexHtml() { return
			"<!DOCTYPE html><html><head><title>eSE Live - Channels</title>"
			"<style>"
			"*{margin:0;padding:0;box-sizing:border-box}"
			"body{background:#0e0e10;color:#efeff1;font-family:system-ui,-apple-system,sans-serif}"
			".header{background:#18181b;padding:16px 24px;border-bottom:1px solid #2f2f35}"
			".header h1{font-size:22px;font-weight:700}"
			".header h1 span{color:#9147ff}"
			".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;padding:24px}"
			".card{background:#1f1f23;border-radius:8px;overflow:hidden;cursor:pointer;transition:transform .15s}"
			".card:hover{transform:translateY(-4px)}"
			".card .thumb{height:180px;background:#000;display:flex;align-items:center;justify-content:center;color:#666;font-size:14px}"
			".card .info{padding:12px}"
			".card .title{font-weight:600;font-size:15px;margin-bottom:4px}"
			".card .meta{color:#adadb8;font-size:13px}"
			".live-dot{display:inline-block;width:8px;height:8px;background:#e74c3c;border-radius:50%;margin-right:4px;animation:pulse 1.5s infinite}"
			"@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}"
			".badge{background:#e74c3c;color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:700}"
			".empty{text-align:center;padding:80px 24px;color:#666;font-size:16px}"
			"</style></head><body>"
			"<div class='header'><h1><span>eSE</span> Live Channels</h1></div>"
			"<div class='grid' id='g'></div>"
			"<div class='empty' id='e'>Loading channels...</div>"
			"<script>"
			// SEC: broadcaster-supplied title/category/quality must be HTML-escaped
			// before being inserted into the DOM. A malicious peer publishing a
			// title like <img src=x onerror=fetch('/api/live/broadcast/stop')>
			// would otherwise execute in any viewer that opens this page.
			"function esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'})[c]})}"
			// M1: B = the /s/{ses}/ prefix when the page is served token-routed,
			// "" when served at /live directly — keeps every fetch and link
			// inside the authenticated namespace.
			"const B=location.pathname.replace(/\\/live\\/?$/,'');"
			"function r(){fetch(B+'/api/live/channels').then(r=>r.json()).then(d=>{"
			"const g=document.getElementById('g'),e=document.getElementById('e');"
			"g.innerHTML='';"
			"if(!d.channels||d.channels.length===0){e.textContent='No live channels right now.';e.style.display='block';return}"
			"e.style.display='none';"
			"d.channels.forEach(c=>{"
			"const card=document.createElement('div');card.className='card';"
			"card.onclick=()=>location.href=B+'/live/'+encodeURIComponent(c.hash);"
			"card.innerHTML='<div class=\"thumb\"><span class=\"badge\">LIVE</span></div>'"
			"+'<div class=\"info\"><div class=\"title\"><span class=\"live-dot\"></span>'+esc(c.title)+'</div>'"
			"+'<div class=\"meta\">'+esc(c.category)+' | '+esc(c.quality)+' | '+esc(c.viewers)+' viewers</div></div>';"
			"g.appendChild(card)})})"
			".catch(()=>{document.getElementById('e').textContent='Failed to load channels.'})}"
			"r();setInterval(r,5000);"
			"</script></body></html>";

}
std::string SubstitutePlayerHash(const char* format, const std::string& hash) { std::string out; unsigned substitutions=0; for (const char* p=format; *p; ++p) { if (*p!='%') { out+=*p; continue; } ++p; if (*p=='%') out+='%'; else if (*p=='s') { out+=hash; ++substitutions; } else { out+='%'; out+=*p; } } return substitutions==3 ? out : std::string(); }
static std::string LivePlayerHtml(const std::string& hash) { static const char* const format =
			"<!DOCTYPE html><html><head><title>eSE Live</title>"
			"<script src='https://cdn.jsdelivr.net/npm/hls.js@latest'></script>"
			"<style>"
			"*{margin:0;padding:0;box-sizing:border-box}"
			"body{background:#0e0e10;color:#efeff1;font-family:system-ui}"
			".player{max-width:1280px;margin:0 auto}"
			"video{width:100%%;background:#000;display:block}"
			".info{padding:16px}"
			".info h1{font-size:20px;margin-bottom:8px}"
			".badge{background:#e74c3c;color:#fff;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:700;margin-right:8px}"
			".meta{color:#adadb8;font-size:14px}"
			".back{display:inline-block;color:#9147ff;text-decoration:none;padding:12px 16px;font-size:14px}"
			".back:hover{text-decoration:underline}"
			"</style></head><body>"
			"<a class='back' href='/live'>< Back to channels</a>"
			"<div class='player'>"
			"<video id='v' controls autoplay muted></video>"
			"<div class='info'><h1><span class='badge'>LIVE</span>Stream</h1>"
			"<div class='meta' id='m'>Connecting...</div></div></div>"
			"<script>"
			// M1: same B-prefix trick as the channels page; also fixes the back
			// link so navigation never falls out of the /s/{ses}/ namespace.
			"const v=document.getElementById('v');"
			"const B=location.pathname.split('/live/')[0];"
			"document.querySelector('.back').href=B+'/live';"
			"const src=B+'/api/live/%s/stream.m3u8';"
			// window.Hls guard: with no internet the CDN script never loads and a
			// bare Hls.isSupported() would throw, killing the native-HLS fallback
			// below (Safari/iOS plays the stream without hls.js).
			"if(window.Hls&&Hls.isSupported()){"
			"const h=new Hls({"
			"liveSyncDurationCount:3,"
			"liveMaxLatencyDurationCount:8,"
			"liveDurationInfinity:true,"
			"maxBufferLength:30,"
			"maxMaxBufferLength:60,"
			"maxBufferHole:2,"
			"highBufferWatchdogPeriod:2,"
			"nudgeOffset:0.5,"
			"manifestLoadingMaxRetry:50,"
			"levelLoadingMaxRetry:50,"
			"fragLoadingMaxRetry:50"
			"});"
			"h.loadSource(src);h.attachMedia(v);"
			"h.on(Hls.Events.MANIFEST_PARSED,()=>v.play());"
			// Audio-distortion fix (2026-06): hls.js requires the two-step media
			// recovery — if a second fatal mediaError lands shortly after a
			// recoverMediaError(), swapAudioCodec() must be called first or the
			// audio is re-appended with the wrong AAC/HE-AAC signaling and plays
			// at the wrong sample rate (the deep/slow audio after stalls).
			"let mErrAt=0;"
			"h.on(Hls.Events.ERROR,(e,d)=>{"
			"if(!d.fatal)return;"
			"if(d.type==='mediaError'){"
			"const n=Date.now();"
			"if(n-mErrAt<6000){h.swapAudioCodec()}"
			"mErrAt=n;"
			"h.recoverMediaError()"
			"}"
			"else{setTimeout(()=>{h.loadSource(src);h.attachMedia(v)},3000)}"
			"});"
			"setInterval(()=>{if(v.paused&&v.readyState>=2)v.play()},2000);"
			// Ghost-viewer fix (2026-06): tell eMule we left when the page goes
			// away (navigation/close). keepalive lets the request outlive the
			// page. The 60 s idle watchdog in Process() is the backstop for
			// killed tabs where this never fires.
			"addEventListener('pagehide',()=>{try{fetch(B+'/api/live/leave?key=%s',{keepalive:true})}catch(_){}});"
			"const langNames={eng:'English',spa:'Spanish',fre:'French',ger:'German',ita:'Italian',por:'Portuguese',jpn:'Japanese',kor:'Korean',chi:'Chinese',rus:'Russian',ara:'Arabic',und:'Track'};"
			"const langFlags={eng:'[EN]',spa:'[ES]',fre:'[FR]',ger:'[DE]',ita:'[IT]',por:'[PT]',jpn:'[JP]',rus:'[RU]',kor:'[KR]',chi:'[CN]',ara:'[AR]',und:''};"
			"function buildAudioSel(tracks,setFn){"
			"if(document.getElementById('audioSel'))return;"
			"if(!tracks||tracks.length<2)return;"
			"const sel=document.createElement('select');"
			"sel.id='audioSel';"
			"sel.style.cssText='position:absolute;top:10px;right:10px;z-index:100;background:rgba(0,0,0,0.7);color:#fff;border:1px solid #555;padding:8px 14px;border-radius:8px;font-size:14px;cursor:pointer;backdrop-filter:blur(8px)';"
			"for(let i=0;i<tracks.length;i++){"
			"const lang=tracks[i].lang||tracks[i].language||'und';"
			"const flag=langFlags[lang]||'';"
			"const name=flag+' '+(langNames[lang]||lang)+' '+(i+1);"
			"sel.innerHTML+='<option value=\"'+i+'\">'+name+'</option>';"
			"}"
			"sel.onchange=()=>setFn(parseInt(sel.value));"
			"document.querySelector('.player').style.position='relative';"
			"document.querySelector('.player').appendChild(sel);"
			"}"
			"h.on(Hls.Events.AUDIO_TRACKS_UPDATED,()=>{"
			"const t=h.audioTrackController?h.audioTrackController.audioTracks:[];"
			"buildAudioSel(t,(i)=>{h.audioTrack=i});"
			"});"
			"v.addEventListener('loadedmetadata',()=>{"
			"if(v.audioTracks&&v.audioTracks.length>=2){"
			"const t=Array.from(v.audioTracks).map(a=>({lang:a.language||'und'}));"
			"buildAudioSel(t,(i)=>{"
			"for(let j=0;j<v.audioTracks.length;j++)v.audioTracks[j].enabled=(j===i);"
			"});"
			"}"
			"});"
			"}else if(v.canPlayType('application/vnd.apple.mpegurl')){v.src=src}"
			// SEC: same escaping concern as the channels grid - title is broadcaster-controlled.
			"function esc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'})[c]})}"
			"fetch(B+'/api/live/channels').then(r=>r.json()).then(d=>{"
			"const ch=d.channels.find(c=>c.hash==='%s');"
			"if(ch){document.querySelector('h1').innerHTML='<span class=\"badge\">LIVE</span> '+esc(ch.title);"
			"document.getElementById('m').textContent=ch.category+' | '+ch.quality+' | '+ch.viewers+' viewers'}});"
			"</script></body></html>"
; return SubstitutePlayerHash(format, hash); }
bool Page(W11LegacyOperation operation, const W11LegacyRequest& request, W11LegacyResponse& response) {
	response.body = operation == W11LegacyOperation::Dashboard ? DashboardHtml() : operation == W11LegacyOperation::LiveIndex ? LiveIndexHtml() : LivePlayerHtml(request.resource);
	if (response.body.empty()) return false;
	response.header = PageHeader(response.body, operation == W11LegacyOperation::Dashboard);
	return true;
}
const char* B(bool value) { return value ? "true" : "false"; }
std::string LegacyHeader(const std::string& body, bool post_json_no_store = false) { return std::string("HTTP/1.1 200 OK\r\nServer: eMule\r\nConnection: close\r\nContent-Type: text/html\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: http://localhost:3000\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\nAccess-Control-Expose-Headers: X-CSRF-Token\r\nContent-Type: application/json\r\n") + (post_json_no_store ? "Cache-Control: no-store\r\n" : "") + "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n"; }
std::string Escape(const std::string& text) { std::string out; static const char hex[]="0123456789abcdef"; for (unsigned char c:text) { if(c=='"'||c=='\\') {out+='\\';out+=static_cast<char>(c);} else if(c=='\b')out+="\\b";else if(c=='\f')out+="\\f";else if(c=='\n')out+="\\n";else if(c=='\r')out+="\\r";else if(c=='\t')out+="\\t";else if(c<32){out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}else out+=static_cast<char>(c); } return out; }
bool Netlab(const W11LegacyPort& port, W11LegacyResponse& response) { if(!port.read_netlab_report)return false;W11NetlabReportSnapshot s;if(!port.read_netlab_report(port.context,s))return false;const char* nat=!s.firewalled?"open_or_mapped":s.hole_sym_nat_fail?"symmetric_or_cgnat_suspected":"lowid_or_double_nat";const char* layer=s.kad3_requests?"punch3":s.hole_attempts?"punch2":s.keepalive_pings?"keepalive":s.has_ipv6?"ipv6":"direct";const char* fallback=s.hole_success?"none":s.hole_sym_nat_fail?"punch_timeout_or_nat_mapping_changed":!s.kad_connected?"kad_disconnected":"not_observed";std::ostringstream o;o.imbue(std::locale::classic());o<<"{\"schema\":\"ESE_NETLAB_REPORT_V1\",\"version\":\""<<Escape(s.version)<<"\",\"cohort\":{\"consent\":\""<<Escape(s.consent)<<"\",\"enabled\":"<<B(s.enabled)<<"},\"network\":{\"ipv4\":"<<B(s.has_ipv4)<<",\"ipv6\":"<<B(s.has_ipv6)<<",\"nat_estimated\":\""<<nat<<"\"},\"last_layer_attempted\":\""<<layer<<"\",\"fallback_reason\":\""<<fallback<<"\",\"punch2\":{\"attempts\":"<<s.hole_attempts<<",\"pinhole_confirmed\":"<<s.hole_success<<",\"nat_failures\":"<<s.hole_sym_nat_fail<<",\"spray_extra_packets\":"<<s.hole_spray<<"},\"punch3\":{\"requests\":"<<s.kad3_requests<<",\"forwarded\":"<<s.kad3_forwarded<<",\"signaling_success\":"<<s.kad3_success<<"},\"keepalive\":{\"running\":"<<B(s.keepalive_running)<<",\"pings\":"<<s.keepalive_pings<<",\"pongs\":"<<s.keepalive_pongs<<",\"peers\":"<<s.keepalive_peers<<"},\"utp_connected\":"<<B(s.utp_connected)<<",\"utp_connected_sockets\":"<<s.utp_sockets<<",\"bytes\":{\"session_received\":"<<s.session_received<<",\"session_sent\":"<<s.session_sent<<",\"relay_forwarded_kb\":"<<s.relay_kb<<"},\"privacy\":{\"full_ip_stored\":false,\"central_telemetry\":false}}";response.body=o.str();response.header="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: "+std::to_string(response.body.size())+"\r\n\r\n";return true; }
bool Echo(const W11LegacyRequest& q,const W11LegacyPort&p,W11LegacyResponse&r){if(!p.run_tunnel_echo)return false;int n=q.bytes.empty()?1024:std::atoi(q.bytes.c_str());if(n<0)n=0;std::vector<std::uint8_t> payload(static_cast<std::size_t>(n));for(std::size_t i=0;i<payload.size();++i)payload[i]=static_cast<std::uint8_t>((i*31u+7u)&0xff);std::vector<std::uint8_t> reply;bool ok=false;try{ok=p.run_tunnel_echo(p.context,payload,reply);}catch(...){ }const bool match=ok&&reply.size()==payload.size()&&(payload.empty()||std::equal(payload.begin(),payload.end(),reply.begin()));r.body="{\"ok\":"+std::string(B(ok))+",\"bytes\":"+std::to_string(n)+",\"replied\":"+std::to_string(reply.size())+",\"match\":"+B(match)+"}";r.header=LegacyHeader(r.body);return true;}
bool Ping(const W11LegacyRequest&q,const W11LegacyPort&p,W11LegacyResponse&r){if(!p.run_tunnel_ping)return false;const std::string text=q.text.empty()?"hello":q.text;std::string reply;bool ok=false;try{ok=p.run_tunnel_ping(p.context,text,reply);}catch(...){ }r.body=ok?"{\"ok\":true,\"sent\":\""+Escape(text)+"\",\"received\":\""+Escape(reply)+"\"}":"{\"ok\":false,\"reason\":\"no active circuit or timeout - build a 2-hop circuit first via test_circuit?hops=2\"}";r.header=LegacyHeader(r.body);return true;}
bool Circuits(const W11LegacyPort&p,W11LegacyResponse&r){if(!p.read_circuits)return false;std::vector<W11CircuitSnapshot> all;if(!p.read_circuits(p.context,all))return false;std::ostringstream o;o.imbue(std::locale::classic());o<<"{\"total\":"<<all.size()<<",\"circuits\":[";for(std::size_t i=0;i<all.size();++i){const auto&s=all[i];if(i)o<<',';const char* state=s.state==0?"Pending":s.state==1?"HalfBuilt":s.state==2?"Built":s.state==3?"Active":s.state==4?"Destroyed":"?";const char* abort=s.abort_reason==1?"STRICT_V1":s.abort_reason==2?"PIN_MISMATCH":s.abort_reason==3?"CAPS_FLOOR":s.abort_reason==4?"SIG_FAIL":s.abort_reason==5?"HANDSHAKE_TIMEOUT":s.abort_reason==6?"EXTEND_TIMEOUT":"NONE";o<<"{\"circ_id\":\"0x"<<std::uppercase<<std::hex<<std::setw(8)<<std::setfill('0')<<s.circ_id<<std::dec<<"\",\"role\":\""<<(s.role==0?"Originator":"Relay")<<"\",\"state\":\""<<state<<"\",\"age_ms\":"<<s.age_ms<<",\"hop_count\":"<<s.hop_count<<",\"forwarding\":"<<B(s.next_hop_set)<<",\"next_circ_id\":\"0x"<<std::uppercase<<std::hex<<std::setw(8)<<std::setfill('0')<<s.next_circ_id<<std::dec<<"\",\"auth_ok\":"<<B(s.auth_ok)<<",\"strict3\":"<<B(s.strict3)<<",\"class5_shaped\":"<<B(s.shaped)<<",\"traffic_shaping_exposed\":"<<B(s.shaping_exposed)<<",\"abort_reason\":\""<<abort<<"\"}";}o<<"]}";r.body=o.str();r.header=LegacyHeader(r.body);return true;}
bool Peers(const W11LegacyPort& p, W11LegacyResponse& r) { if (!p.read_peers) return false; std::vector<W11PeerSnapshot> all; std::size_t count = 0; try { if (!p.read_peers(p.context, all, count)) return false; } catch (...) { return false; } std::size_t authenticated=0;for(const W11PeerSnapshot& s:all)if(s.auth_ready)++authenticated;std::ostringstream o; o.imbue(std::locale::classic()); o << "{\"totalConnected\":" << all.size() << ",\"forkTunnelingCapable\":" << count << ",\"authenticatedTunnelCapable\":" << authenticated << ",\"peers\":["; for (std::size_t i=0;i<all.size();++i) { const W11PeerSnapshot& s=all[i]; if(i)o<<','; o << "{\"ip\":\"" << s.ip << "\",\"address\":\"" << s.address << "\",\"port\":" << s.port << ",\"forkCaps\":\"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << s.fork_caps << std::dec << "\",\"eseCaps\":\"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << s.ese_caps << std::dec << "\",\"isFork\":" << B((s.ese_caps & 0x00000100u) != 0) << ",\"authReady\":" << B(s.auth_ready) << ",\"hashReady\":" << B(s.hash_ready) << ",\"nodePubReady\":" << B(s.node_pub_ready) << ",\"authCap\":" << B(s.auth_cap) << ",\"dataplaneCap\":" << B(s.dataplane_cap) << "}"; } o << "]}"; r.body=o.str();r.header=LegacyHeader(r.body);return true; }
bool TestCircuit(const W11LegacyRequest& q, const W11LegacyPort& p, W11LegacyResponse& r) { const unsigned hops=q.hops=="3"?3:q.hops=="2"?2:1;std::uint32_t id=0; if(p.request_test_circuit) try { p.request_test_circuit(p.context,hops,id); } catch (...) {} if(!id) r.body=hops==3?"{\"ok\":false,\"reason\":\"strict3 unavailable: need 3 authenticated shaped IPv6 peers with verified /48+ASN diversity and no repeated known operator group - check /api/live/privacy/peers\"}":hops==2?"{\"ok\":false,\"reason\":\"two-hop circuit unavailable: need 2 distinct connected fork-capable peers - no loopback downgrade\"}":"{\"ok\":false,\"reason\":\"no connected fork-capable peers - check /api/live/privacy/peers\"}"; else { std::ostringstream o;o.imbue(std::locale::classic());o<<"{\"ok\":true,\"circuit_id\":\"0x"<<std::nouppercase<<std::hex<<std::setw(8)<<std::setfill('0')<<id<<std::dec<<"\",\"hops_requested\":"<<hops<<",\"note\":\"poll /api/live/privacy and /api/live/privacy/circuits to watch handshake progress\"}";r.body=o.str(); }r.header=LegacyHeader(r.body);return true; }
bool HexDigest(const std::string& text) { return text.size()==64 && std::all_of(text.begin(),text.end(),[](unsigned char c){return std::isxdigit(c)!=0;}); }
std::uint64_t Unsigned(const std::string& text, int base) { return std::strtoull(text.c_str(), nullptr, base); }
std::uint32_t Unsigned32(const std::string& text, int base) { const std::uint64_t value=Unsigned(text,base);return value>std::numeric_limits<std::uint32_t>::max()?std::numeric_limits<std::uint32_t>::max():static_cast<std::uint32_t>(value); }
std::uint32_t Drain(const std::string& text, bool release) { int value=text.empty()?(release?0:300):std::atoi(text.c_str());if(release&&value<=0)value=300;if(!release&&value<0)value=0;if(value>86400)value=86400;return static_cast<std::uint32_t>(value); }
bool ReadRelease(const W11LegacyPort& p, bool local, W11ReleaseSnapshot& s) { if (!p.read_release) return true; try { return p.read_release(p.context,local,s); } catch (...) { return true; } }
bool Release(const W11LegacyRequest& q, const W11LegacyPort& p, W11LegacyResponse& r) { bool ok=true;std::string error; if(!q.enabled.empty()){if(!q.loopback){ok=false;error="local_only";}else if(q.enabled!="0"&&q.enabled!="1"){ok=false;error="bad_enabled";}else {bool consumed=false;try{consumed=p.consume_release_challenge&&p.consume_release_challenge(p.context,q.challenge);}catch(...){}if(!consumed){ok=false;error="challenge_required_or_expired";}else {W11ReleaseEvidence evidence;const W11ReleaseEvidence* supplied=nullptr;if(q.enabled=="1"){if(q.confirm!="ENABLE_KAD6_PUBLIC_EXIT"){ok=false;error="confirmation_required";}else if(!q.field_sha256.empty()||!q.audit_sha256.empty()){evidence.field_sha256=q.field_sha256;evidence.audit_sha256=q.audit_sha256;evidence.observed_from=Unsigned(q.observed_from,10);evidence.observed_to=Unsigned(q.observed_to,10);evidence.admission_attempts=Unsigned(q.admission_attempts,10);evidence.admission_ppm=Unsigned32(q.admission_ppm,10);evidence.headroom_bps=Unsigned(q.headroom_bps,10);evidence.gate_mask=static_cast<std::uint16_t>(Unsigned32(q.gate_mask,0));evidence.valid_until=Unsigned(q.valid_until,10);if(!HexDigest(q.field_sha256)||!HexDigest(q.audit_sha256)||q.observed_from.empty()||q.observed_to.empty()||q.admission_attempts.empty()||q.admission_ppm.empty()||q.headroom_bps.empty()||q.gate_mask.empty()){ok=false;error="incomplete_or_bad_evidence";}else supplied=&evidence;} }if(ok){try{ok=p.request_release&&p.request_release(p.context,q.enabled=="1",supplied,Drain(q.drain_seconds,true));}catch(...){ok=false;}if(!ok)error="gate_rejected_or_runtime_unhealthy";}}}}W11ReleaseSnapshot s;ReadRelease(p,q.loopback,s);r.body="{\"ok\":"+std::string(B(ok))+",\"error\":\""+Escape(error)+"\",\"status\":\""+Escape(s.status)+"\",\"challenge\":\""+Escape(s.challenge)+"\",\"operator_opt_in\":"+B(s.operator_opt_in)+",\"evidence_present\":"+B(s.evidence_present)+",\"evidence_valid\":"+B(s.evidence_valid)+",\"runtime_healthy\":"+B(s.runtime_healthy)+",\"public_exit_enabled\":"+B(s.public_exit_enabled)+",\"beta_exit_opt_in\":"+B(s.beta_exit_opt_in)+",\"beta_exit_enabled\":"+B(s.beta_exit_enabled)+",\"gate_mask\":"+std::to_string(s.evidence.gate_mask)+",\"observed_from\":"+std::to_string(s.evidence.observed_from)+",\"observed_to\":"+std::to_string(s.evidence.observed_to)+",\"valid_until\":"+std::to_string(s.evidence.valid_until)+",\"admission_attempts\":"+std::to_string(s.evidence.admission_attempts)+",\"admission_ppm\":"+std::to_string(s.evidence.admission_ppm)+",\"headroom_bps\":"+std::to_string(s.evidence.headroom_bps)+"}";r.header=LegacyHeader(r.body,true);return true; }
const char* Band(std::uint64_t value) { return value==0?"zero":value<=4?"1_4":value<=16?"5_16":value<=64?"17_64":"65_plus"; }
bool Hardening(const W11LegacyRequest& q, const W11LegacyPort& p, W11LegacyResponse& r) { bool ok=true;std::string error;if(!q.service.empty()||!q.enabled.empty()){const bool service=q.service=="control"||q.service=="exit_kad"||q.service=="exit_ed2k_dial"||q.service=="exit_ed2k_full";if(!q.loopback){ok=false;error="local_only";}else if(!service||(q.enabled!="0"&&q.enabled!="1")){ok=false;error="bad_service_or_enabled";}else {try{ok=p.request_hardening&&p.request_hardening(p.context,q.service,q.enabled=="1",Drain(q.drain_seconds,false));}catch(...){ok=false;}if(!ok)error="release_gate_or_main_thread_timeout";}}W11HardeningSnapshot s;if(p.read_hardening)try{p.read_hardening(p.context,s);}catch(...){}std::ostringstream o;o.imbue(std::locale::classic());o<<"{\"ok\":"<<B(ok)<<",\"error\":\""<<Escape(error)<<"\",\"health\":\""<<((s.source_epoch_store_failed||s.shaping_exposed_circuits!=0)?"degraded":"healthy")<<"\",\"revision\":"<<s.revision<<",\"services\":[";for(std::size_t i=0;i<s.services.size();++i){const W11HardeningServiceSnapshot& x=s.services[i];if(i)o<<',';o<<"{\"service\":\""<<Escape(x.service)<<"\",\"state\":\""<<Escape(x.state)<<"\",\"changed_at\":"<<x.changed_at<<",\"drain_deadline\":"<<x.drain_deadline<<",\"admitting\":"<<B(x.admitting)<<"}";}o<<"],\"occupancy\":{\"leases\":\""<<Band(s.active_leases)<<"\",\"publishes\":\""<<Band(s.active_publishes)<<"\",\"dial_streams\":\""<<Band(s.dial_streams)<<"\",\"full_streams\":\""<<Band(s.full_streams)<<"\",\"shaping_exposed\":"<<B(s.shaping_exposed_circuits!=0)<<"},\"source_pipeline\":{\"advertised\":"<<s.origin_advertise_success_total<<",\"recovered\":"<<s.origin_source_recovered_total<<"},\"source_epoch_store_failed\":"<<B(s.source_epoch_store_failed)<<",\"metrics\":{\"window_ready\":"<<B(s.metrics_ready)<<",\"window_start\":"<<s.metrics_start<<",\"window_end\":"<<s.metrics_end<<",\"fixed_series\":"<<s.metrics_fixed_series<<",\"exported_series\":"<<s.metrics_exported_series<<"},\"economy\":{\"measurement_ready\":"<<B(s.economy_measurement_ready)<<",\"strict_recommended\":"<<B(s.strict_recommended)<<",\"services\":[";for(std::size_t i=0;i<s.economy.size();++i){const W11HardeningEconomySnapshot& x=s.economy[i];if(i)o<<',';o<<"{\"service\":\""<<Escape(x.service)<<"\",\"rho\":";if(x.rho_present&&std::isfinite(x.rho))o<<std::fixed<<std::setprecision(6)<<x.rho;else o<<"null";o<<",\"sealed\":"<<B(x.sealed)<<",\"starts_at\":"<<x.starts_at<<",\"ends_at\":"<<x.ends_at<<",\"samples\":"<<x.samples<<",\"admission_attempts\":"<<x.admission_attempts<<",\"admission_successes\":"<<x.admission_successes<<",\"admission_ratio\":"<<std::fixed<<std::setprecision(6)<<x.admission_ratio<<",\"rho_p50\":"<<std::fixed<<std::setprecision(6)<<x.rho_p50<<",\"rho_p95\":"<<std::fixed<<std::setprecision(6)<<x.rho_p95<<"}";}o<<"]},\"exit_notice\":{\"running\":"<<B(s.exit_notice_running)<<",\"port\":"<<s.exit_notice_port<<",\"requests\":\""<<Band(s.exit_notice_requests)<<"\",\"rejected\":\""<<Band(s.exit_notice_rejected)<<"\",\"bytes_sent\":\""<<Band(s.exit_notice_bytes_sent)<<"\"}}";r.body=o.str();r.header=LegacyHeader(r.body,true);return true; }
} // namespace

bool BuildW11LegacyStaticFile(const W11StaticFileRequest& request, W11LegacyResponse& response) {
	response = W11LegacyResponse();
	if (request.url.empty()) return false;
	std::string relative = request.url;
	std::replace(relative.begin(), relative.end(), '/', '\\');
	if (!relative.empty() && relative[0] == '\\') relative.erase(0, 1);
	response.file_response = true;
	response.file_path = request.web_root + relative;
	response.file_name = relative;
	response.public_path = request.public_path.empty() ? request.url : request.public_path;
	response.file_range = request.range;
	response.etag = request.etag;
	response.last_modified = request.last_modified;
	response.maximum_bytes = request.maximum_bytes;
	response.concurrent = false;
	response.allow_empty = true;
	return true;
}

bool RunW11LiveLegacyApi(const W11LegacyRequest& input, const W11LegacyPort& port, W11LegacyResponse& response) {
	response = W11LegacyResponse();
	const W11LegacyRequest& request = input;
	if (request.operation == W11LegacyOperation::Hls && !SafeLeaf(request.resource)) return false;
	if (request.operation == W11LegacyOperation::LivePlayer && !HexKey16(request.resource)) return false;
	switch (request.operation) {
	case W11LegacyOperation::Hls: return Hls(request, port, response);
	case W11LegacyOperation::Dashboard: return Page(request.operation, request, response);
	case W11LegacyOperation::NetlabReport: return Netlab(port,response);
	case W11LegacyOperation::TunnelEcho: return Echo(request,port,response);
	case W11LegacyOperation::TunnelPing: return Ping(request,port,response);
	case W11LegacyOperation::Circuits: return Circuits(port,response);
	case W11LegacyOperation::Peers: return Peers(port, response);
	case W11LegacyOperation::TestCircuit: return TestCircuit(request, port, response);
	case W11LegacyOperation::Kad6Release: return Release(request, port, response);
	case W11LegacyOperation::Kad6Hardening: return Hardening(request, port, response);
	case W11LegacyOperation::LiveIndex: return Page(request.operation, request, response);
	case W11LegacyOperation::LivePlayer: return Page(request.operation, request, response);
	}
	return false;
}

bool RunW11LiveLegacyCharacterizationSelfTest(std::string& failure) {
	struct State { unsigned calls = 0, effects = 0, consumed = 0, notes = 0; std::uint32_t admission_ppm = 0; std::uint16_t gate_mask = 0; std::string sequence; } state;
	W11LegacyPort port; port.context = &state;
	port.resolve_hls = [](void* raw, const W11LegacyRequest&, W11HlsSnapshot& response) { ++static_cast<State*>(raw)->calls; response.root_path = "root"; response.root_exists = true; response.viewer_key = "viewer"; return true; };
	port.note_player_fetch = [](void* raw) { ++static_cast<State*>(raw)->notes; };
	W11LegacyRequest request; W11LegacyResponse response;
	request.operation = W11LegacyOperation::Hls; request.resource = "stream.m3u8";
	request.range="bytes=2-7";if (!RunW11LiveLegacyApi(request, port, response) || !response.file_response || response.file_name != "stream.m3u8" || response.file_path != "root\\stream.m3u8" || response.file_range!="bytes=2-7" || response.maximum_bytes != 20ull * 1024ull * 1024ull || !response.cors_wildcard || response.cors_origin!="*" || !response.concurrent || response.allow_empty || state.notes!=0) { failure = "hls root byte-exact"; return false; }
	port.resolve_hls=[](void*,const W11LegacyRequest&,W11HlsSnapshot& s){s.root_path="root";s.root_exists=false;s.viewer_key="viewer";return true;};if(!RunW11LiveLegacyApi(request,port,response)||response.file_path!="root\\viewer\\stream.m3u8"||state.notes!=1){failure="hls fallback note";return false;}
	request.resource = "../secret.ts"; if (RunW11LiveLegacyApi(request, port, response)) { failure = "hls traversal"; return false; }
	request.operation = W11LegacyOperation::LivePlayer; request.resource = "0123456789abcdef0123456789abcdef";
	if (!RunW11LiveLegacyApi(request, port, response)) { failure = "player dispatch"; return false; }
	const std::size_t player1=response.body.find(request.resource),player2=response.body.find(request.resource,player1+1),player3=response.body.find(request.resource,player2+1),player4=response.body.find(request.resource,player3+1);
	if (response.body.size()!=4033 || response.header != "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 4033\r\n\r\n" || player1==std::string::npos || player2==std::string::npos || player3==std::string::npos || player4!=std::string::npos) { failure = "player independent shape"; return false; }
	request.operation = W11LegacyOperation::Dashboard; request.resource.clear(); if (!RunW11LiveLegacyApi(request, port, response) || response.body.size()!=7805 || response.header != "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 7805\r\nCache-Control: no-cache\r\n\r\n") { failure = "dashboard independent shape"; return false; }
	request.operation = W11LegacyOperation::LiveIndex; if (!RunW11LiveLegacyApi(request, port, response) || response.body.size()!=2433 || response.header != "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 2433\r\n\r\n") { failure = "index independent shape"; return false; }
	W11StaticFileRequest staticRequest;staticRequest.web_root="web\\";staticRequest.url="/images/logo.png";staticRequest.public_path="/wire/logo.png";staticRequest.range="bytes=1-2";staticRequest.etag="tag";staticRequest.last_modified="when";staticRequest.maximum_bytes=123;if(!BuildW11LegacyStaticFile(staticRequest,response)||response.file_path!="web\\images\\logo.png"||response.public_path!="/wire/logo.png"||response.file_range!="bytes=1-2"||response.etag!="tag"||response.last_modified!="when"||response.maximum_bytes!=123||response.concurrent||!response.allow_empty){failure="static file byte-exact";return false;}
	port.read_netlab_report=[](void*,W11NetlabReportSnapshot& s){s.version="v\"";s.consent="accepted";s.enabled=s.has_ipv4=s.kad_connected=s.keepalive_running=s.utp_connected=true;s.hole_attempts=2;s.hole_success=1;s.keepalive_pings=3;s.keepalive_pongs=4;s.keepalive_peers=5;s.utp_sockets=6;s.session_received=7;s.session_sent=8;s.relay_kb=9;return true;};request.operation=W11LegacyOperation::NetlabReport;if(!RunW11LiveLegacyApi(request,port,response)||response.body!="{\"schema\":\"ESE_NETLAB_REPORT_V1\",\"version\":\"v\\\"\",\"cohort\":{\"consent\":\"accepted\",\"enabled\":true},\"network\":{\"ipv4\":true,\"ipv6\":false,\"nat_estimated\":\"open_or_mapped\"},\"last_layer_attempted\":\"punch2\",\"fallback_reason\":\"none\",\"punch2\":{\"attempts\":2,\"pinhole_confirmed\":1,\"nat_failures\":0,\"spray_extra_packets\":0},\"punch3\":{\"requests\":0,\"forwarded\":0,\"signaling_success\":0},\"keepalive\":{\"running\":true,\"pings\":3,\"pongs\":4,\"peers\":5},\"utp_connected\":true,\"utp_connected_sockets\":6,\"bytes\":{\"session_received\":7,\"session_sent\":8,\"relay_forwarded_kb\":9},\"privacy\":{\"full_ip_stored\":false,\"central_telemetry\":false}}"||response.header!="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: "+std::to_string(response.body.size())+"\r\n\r\n"){failure="netlab byte-exact";return false;}
	port.run_tunnel_echo=[](void*,const std::vector<std::uint8_t>& in,std::vector<std::uint8_t>& out){out=in;return true;};request.operation=W11LegacyOperation::TunnelEcho;request.bytes="3";if(!RunW11LiveLegacyApi(request,port,response)||response.body!="{\"ok\":true,\"bytes\":3,\"replied\":3,\"match\":true}"||response.header.find("Content-Type: text/html\r\n")>response.header.find("Content-Type: application/json\r\n")){failure="echo byte-exact";return false;}
	port.run_tunnel_ping=[](void*,const std::string& in,std::string& out){out=in+"\"";return true;};request.operation=W11LegacyOperation::TunnelPing;request.text="x\n";if(!RunW11LiveLegacyApi(request,port,response)||response.body!="{\"ok\":true,\"sent\":\"x\\n\",\"received\":\"x\\n\\\"\"}"){failure="ping byte-exact";return false;}
	port.read_circuits=[](void*,std::vector<W11CircuitSnapshot>& out){out.push_back({1,2,3,4,0,3,6,true,true,false,true,false});return true;};request.operation=W11LegacyOperation::Circuits;if(!RunW11LiveLegacyApi(request,port,response)||response.body!="{\"total\":1,\"circuits\":[{\"circ_id\":\"0x00000001\",\"role\":\"Originator\",\"state\":\"Active\",\"age_ms\":2,\"hop_count\":4,\"forwarding\":true,\"next_circ_id\":\"0x00000003\",\"auth_ok\":true,\"strict3\":false,\"class5_shaped\":true,\"traffic_shaping_exposed\":false,\"abort_reason\":\"EXTEND_TIMEOUT\"}]}"){failure="circuits byte-exact";return false;}
	port.read_peers=[](void*,std::vector<W11PeerSnapshot>& out,std::size_t& capable){out.push_back({"1.2.3.4","v6",4662,1,0x100,true,true,true,true,true});capable=1;return true;};request.operation=W11LegacyOperation::Peers;if(!RunW11LiveLegacyApi(request,port,response)||response.body!="{\"totalConnected\":1,\"forkTunnelingCapable\":1,\"authenticatedTunnelCapable\":1,\"peers\":[{\"ip\":\"1.2.3.4\",\"address\":\"v6\",\"port\":4662,\"forkCaps\":\"0x00000001\",\"eseCaps\":\"0x00000100\",\"isFork\":true,\"authReady\":true,\"hashReady\":true,\"nodePubReady\":true,\"authCap\":true,\"dataplaneCap\":true}]}"){failure="peers byte-exact";return false;}
	port.request_test_circuit=[](void* raw,unsigned hops,std::uint32_t& id){State& s=*static_cast<State*>(raw);++s.effects;s.sequence+=char('0'+hops);id=0x2a;return true;};request.operation=W11LegacyOperation::TestCircuit;request.hops="2";if(!RunW11LiveLegacyApi(request,port,response)||response.body!="{\"ok\":true,\"circuit_id\":\"0x0000002a\",\"hops_requested\":2,\"note\":\"poll /api/live/privacy and /api/live/privacy/circuits to watch handshake progress\"}"||state.sequence!="2"){failure="test circuit byte-exact";return false;}
	port.consume_release_challenge=[](void* raw,const std::string& token){State& s=*static_cast<State*>(raw);++s.consumed;s.sequence+="C"+token;return token=="ok";};port.request_release=[](void* raw,bool enabled,const W11ReleaseEvidence* evidence,std::uint32_t drain){State& s=*static_cast<State*>(raw);++s.effects;s.sequence+=enabled?"R":"r";if(evidence){s.admission_ppm=evidence->admission_ppm;s.gate_mask=evidence->gate_mask;}return evidence!=nullptr&&drain==300;};port.read_release=[](void*,bool local,W11ReleaseSnapshot& s){s.status="ready";s.challenge=local?"next":"";s.operator_opt_in=s.evidence_present=s.evidence_valid=s.runtime_healthy=s.public_exit_enabled=s.beta_exit_opt_in=s.beta_exit_enabled=true;s.evidence.gate_mask=7;s.evidence.observed_from=1;s.evidence.observed_to=2;s.evidence.valid_until=3;s.evidence.admission_attempts=4;s.evidence.admission_ppm=5;s.evidence.headroom_bps=6;return true;};request.operation=W11LegacyOperation::Kad6Release;request.loopback=true;request.enabled="1";request.challenge="ok";request.confirm="wrong";state.sequence.clear();const unsigned effectsBefore=state.effects;if(!RunW11LiveLegacyApi(request,port,response)||response.body.find("\"error\":\"confirmation_required\"")==std::string::npos||state.sequence!="Cok"||state.effects!=effectsBefore){failure="release consume order";return false;}
	request.confirm="ENABLE_KAD6_PUBLIC_EXIT";request.field_sha256=std::string(64,'a');request.audit_sha256=std::string(64,'b');request.observed_from="1";request.observed_to="2";request.admission_attempts="4";request.admission_ppm="5";request.headroom_bps="6";request.gate_mask="7";request.valid_until="3";state.sequence.clear();const std::string releaseBody="{\"ok\":true,\"error\":\"\",\"status\":\"ready\",\"challenge\":\"next\",\"operator_opt_in\":true,\"evidence_present\":true,\"evidence_valid\":true,\"runtime_healthy\":true,\"public_exit_enabled\":true,\"beta_exit_opt_in\":true,\"beta_exit_enabled\":true,\"gate_mask\":7,\"observed_from\":1,\"observed_to\":2,\"valid_until\":3,\"admission_attempts\":4,\"admission_ppm\":5,\"headroom_bps\":6}";const std::string releaseHeader="HTTP/1.1 200 OK\r\nServer: eMule\r\nConnection: close\r\nContent-Type: text/html\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: http://localhost:3000\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\nAccess-Control-Expose-Headers: X-CSRF-Token\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: "+std::to_string(releaseBody.size())+"\r\n\r\n";if(!RunW11LiveLegacyApi(request,port,response)||response.body!=releaseBody||response.header!=releaseHeader||state.sequence!="CokR"){failure="release response byte-exact";return false;}
	request.admission_ppm="4294967296";request.gate_mask="0x100000000";state.sequence.clear();if(!RunW11LiveLegacyApi(request,port,response)||state.admission_ppm!=std::numeric_limits<std::uint32_t>::max()||state.gate_mask!=std::numeric_limits<std::uint16_t>::max()){failure="release uint32 overflow compatibility";return false;}request.admission_ppm="5";request.gate_mask="7";
	const unsigned releaseBefore=state.effects;request.challenge="expired";if(!RunW11LiveLegacyApi(request,port,response)||response.body.find("\"error\":\"challenge_required_or_expired\"")==std::string::npos||state.effects!=releaseBefore){failure="release challenge no mutation";return false;}request.challenge="ok";request.field_sha256="bad";if(!RunW11LiveLegacyApi(request,port,response)||response.body.find("\"error\":\"incomplete_or_bad_evidence\"")==std::string::npos||state.effects!=releaseBefore){failure="release evidence no mutation";return false;}request.field_sha256=std::string(64,'a');
	port.request_hardening=[](void* raw,const std::string& service,bool enabled,std::uint32_t drain){State& s=*static_cast<State*>(raw);++s.effects;s.sequence=service+(enabled?"1":"0")+std::to_string(drain);return true;};port.read_hardening=[](void*,W11HardeningSnapshot& s){s.revision=1;s.services.push_back({"control","enabled",2,0,true});s.active_leases=5;s.origin_advertise_success_total=13;s.origin_source_recovered_total=14;s.metrics_ready=true;s.metrics_start=3;s.metrics_end=4;s.metrics_fixed_series=5;s.metrics_exported_series=6;s.economy_measurement_ready=true;s.strict_recommended=true;s.economy.push_back({"control",true,true,1.25,2.5,3.5,4.5,7,8,9,10,11});s.exit_notice_running=true;s.exit_notice_port=12;s.exit_notice_requests=64;s.exit_notice_rejected=65;s.exit_notice_bytes_sent=0;return true;};request.operation=W11LegacyOperation::Kad6Hardening;request.service="control";request.enabled="0";request.drain_seconds="-4";const std::string hardeningBody="{\"ok\":true,\"error\":\"\",\"health\":\"healthy\",\"revision\":1,\"services\":[{\"service\":\"control\",\"state\":\"enabled\",\"changed_at\":2,\"drain_deadline\":0,\"admitting\":true}],\"occupancy\":{\"leases\":\"5_16\",\"publishes\":\"zero\",\"dial_streams\":\"zero\",\"full_streams\":\"zero\",\"shaping_exposed\":false},\"source_pipeline\":{\"advertised\":13,\"recovered\":14},\"source_epoch_store_failed\":false,\"metrics\":{\"window_ready\":true,\"window_start\":3,\"window_end\":4,\"fixed_series\":5,\"exported_series\":6},\"economy\":{\"measurement_ready\":true,\"strict_recommended\":true,\"services\":[{\"service\":\"control\",\"rho\":1.250000,\"sealed\":true,\"starts_at\":7,\"ends_at\":8,\"samples\":9,\"admission_attempts\":10,\"admission_successes\":11,\"admission_ratio\":2.500000,\"rho_p50\":3.500000,\"rho_p95\":4.500000}]},\"exit_notice\":{\"running\":true,\"port\":12,\"requests\":\"17_64\",\"rejected\":\"65_plus\",\"bytes_sent\":\"zero\"}}";const std::string hardeningHeader="HTTP/1.1 200 OK\r\nServer: eMule\r\nConnection: close\r\nContent-Type: text/html\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: http://localhost:3000\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\nAccess-Control-Expose-Headers: X-CSRF-Token\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: "+std::to_string(hardeningBody.size())+"\r\n\r\n";if(!RunW11LiveLegacyApi(request,port,response)||response.body!=hardeningBody||response.header!=hardeningHeader||state.sequence!="control00"){failure="hardening response byte-exact";return false;}const unsigned hardeningBefore=state.effects;request.loopback=false;if(!RunW11LiveLegacyApi(request,port,response)||response.body.find("\"error\":\"local_only\"")==std::string::npos||state.effects!=hardeningBefore){failure="hardening no mutation";return false;}request.loopback=true;request.service="wrong";if(!RunW11LiveLegacyApi(request,port,response)||response.body.find("\"error\":\"bad_service_or_enabled\"")==std::string::npos||state.effects!=hardeningBefore){failure="hardening validation no mutation";return false;}
	request.operation=W11LegacyOperation::LivePlayer;request.resource = "not-a-stream"; if (RunW11LiveLegacyApi(request, port, response)) { failure = "player hash"; return false; }
	failure.clear(); return true;
}
} } // namespace ese::web
