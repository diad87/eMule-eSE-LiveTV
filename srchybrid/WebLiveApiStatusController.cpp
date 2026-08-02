#include "WebLiveApiStatusController.h"

#include <mutex>
#include <thread>
#include <vector>

namespace eSELive {
WebLiveApiStatusController::WebLiveApiStatusController(const M2AParentPort& parent) : m_parent(parent) {}
M2AModuleHandle M2A_BIND_W8_E988965D5A(const M2AParentPort& parent) { return parent ? MakeM2AModuleHandle(new WebLiveApiStatusController(parent)) : M2AModuleHandle(); }
void M2A_UNBIND_W8_E988965D5A(const M2AParentPort&) {}
} // namespace eSELive

namespace ese { namespace web { namespace {

const char* B(bool value) { return value ? "true" : "false"; }
template <typename T> void N(std::string& out, T value) { out += std::to_string(value); }
void Q(std::string& out, const std::string& value) {
	static const char hex[] = "0123456789abcdef"; out += '"';
	for (const unsigned char c : value) switch (c) {
	case '"': out += "\\\""; break; case '\\': out += "\\\\"; break; case '\b': out += "\\b"; break;
	case '\f': out += "\\f"; break; case '\n': out += "\\n"; break; case '\r': out += "\\r"; break; case '\t': out += "\\t"; break;
	default: if (c < 0x20u) { out += "\\u00"; out += hex[c >> 4u]; out += hex[c & 15u]; } else out += static_cast<char>(c);
	} out += '"';
}
void Field(std::string& out, const char* name, bool value) { out += ",\""; out += name; out += "\":"; out += B(value); }
template <typename T> void Field(std::string& out, const char* name, T value) { out += ",\""; out += name; out += "\":"; N(out, value); }
void Text(std::string& out, const char* name, const std::string& value) { out += ",\""; out += name; out += "\":"; Q(out, value); }
std::string Header(const std::string& body, bool legacy) {
	std::string h = "HTTP/1.1 200 OK\r\n";
	if (legacy) h += "Server: eMule\r\nConnection: close\r\nContent-Type: text/html\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: http://localhost:3000\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\nAccess-Control-Expose-Headers: X-CSRF-Token\r\n";
	else h += "Content-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\n";
	if (legacy) h += "Content-Type: application/json\r\n";
	h += "Content-Length: "; N(h, body.size()); h += "\r\n\r\n"; return h;
}
std::string Status(const W8LiveStatusSnapshot& s, bool local) {
	std::string o = "{\"upnp_critical_error\":"; o += B(s.upnp_critical_error); Field(o,"utp_hole_punch_enabled",s.utp_hole_punch_enabled); Field(o,"web_upnp_active",s.web_upnp_active); Text(o,"upnp_ports_forwarded",s.upnp_ports_forwarded);
	Field(o,"kad_connected",s.kad_connected); Field(o,"kad_configured_mask",s.kad_configured_mask); Field(o,"kad_running_mask",s.kad_running_mask); Field(o,"kad2_running",s.kad2_running); Field(o,"kad2_connected",s.kad2_connected); Field(o,"kad6_running",s.kad6_running); Field(o,"kad6_connected",s.kad6_connected); Field(o,"kad6_verified_contacts",s.kad6_verified_contacts); Field(o,"ed2k_connected",s.ed2k_connected);
	o += ",\"user_hash\":"; if (local) Q(o,s.user_hash); else o += "null";
	o += ",\"connecting_client_count\":"; if (local) N(o,s.connecting_client_count); else o += "null";
	o += ",\"connecting_client_adds\":"; if (local) N(o,s.connecting_client_adds); else o += "null";
	o += ",\"connecting_client_high_water\":"; if (local) N(o,s.connecting_client_high_water); else o += "null";
	o += ",\"connecting_client_duplicate_adds\":"; if (local) N(o,s.connecting_client_duplicate_adds); else o += "null";
	Field(o,"hole_punch_attempts",s.hole_punch_attempts); Field(o,"hole_punch_success",s.hole_punch_success); Field(o,"hole_punch_sym_nat_fail",s.hole_punch_sym_nat_fail); Field(o,"hole_punch_encrypted",s.hole_punch_encrypted); Field(o,"hole_punch_plaintext",s.hole_punch_plaintext); Field(o,"hole_punch_req_recv",s.hole_punch_req_recv); Field(o,"hole_punch_challenge_sent",s.hole_punch_challenge_sent); Field(o,"kad3_rdv_req_sent",s.kad3_rdv_req_sent); Field(o,"kad3_rdv_req_recv",s.kad3_rdv_req_recv); Field(o,"kad3_rdv_challenge_sent",s.kad3_rdv_challenge_sent); Field(o,"kad3_rdv_fwd",s.kad3_rdv_fwd); Field(o,"kad3_rdv_success",s.kad3_rdv_success); Field(o,"keepalive_running",s.keepalive_running); Field(o,"keepalive_pings_sent",s.keepalive_pings_sent); Field(o,"keepalive_pongs_recv",s.keepalive_pongs_recv); Field(o,"keepalive_supernodes",s.keepalive_supernodes); Text(o,"netlab_consent",s.netlab_consent); Text(o,"netlab_advanced_consent",s.netlab_advanced_consent); Text(o,"netlab_contribution_consent",s.netlab_contribution_consent); Field(o,"netlab_enabled",s.netlab_enabled); o += '}'; return o;
}
std::string Key(const std::array<std::uint8_t,16>& key) { static const char h[]="0123456789abcdef"; std::string o; o.reserve(32); for (std::uint8_t c:key) { o += h[c>>4u]; o += h[c&15u]; } return o; }
std::string Channels(const W8LiveChannelSnapshot& c) {
	std::string o = "{\"channels\":["; if (c.broadcasting) { const char* q="SD"; if(c.bitrate>=8000)q="4K"; else if(c.bitrate>=5000)q="FHD"; else if(c.bitrate>=3000)q="HD"; o += "{\"hash\":"; Q(o,Key(c.stream_key)); Text(o,"title",c.title); Text(o,"category",c.category); Text(o,"language",c.language); Field(o,"startedAt",c.started_at); Field(o,"viewers",c.viewer_count); Field(o,"bitrate",c.bitrate); o += ",\"quality\":"; Q(o,q); o += '}'; } o += "]}"; return o;
}
std::string Mesh(const W8LiveMeshSnapshot& m) { std::string o="{\"meshPeers\":"; N(o,m.mesh_peers); Field(o,"pendingRequests",m.pending_requests); Field(o,"chunksServed",m.chunks_served); Field(o,"totalRedistributed",m.total_redistributed); o += ",\"trustLevels\":{\"superSeeders\":"; N(o,m.super_seeders); Field(o,"middle",m.middle_peers); Field(o,"leaf",m.leaf_peers); o += "},\"uploadFloor\":"; N(o,m.upload_floor); o += ",\"emergencyMode\":"; o += B(m.emergency_mode); return o + ",\"source\":\"emule-core\"}"; }
struct ConcurrentStatus {
	std::mutex mutex; W8LiveStatusSnapshot snapshots[2]; unsigned next = 0, calls = 0;
};
bool ReadConcurrentStatus(void* context, W8LiveStatusSnapshot& out) {
	ConcurrentStatus& state = *static_cast<ConcurrentStatus*>(context); std::lock_guard<std::mutex> lock(state.mutex);
	out = state.snapshots[state.next++ % 2]; ++state.calls; return true;
}

} // namespace

bool RunW8LiveStatusApi(W8LiveStatusOperation op, bool loopback, const W8LiveStatusPort& p, W8LiveStatusResponse& r) {
	if (op == W8LiveStatusOperation::Status) { W8LiveStatusSnapshot s; if (p.read_status) p.read_status(p.context,s); r.body=Status(s,loopback); r.header=Header(r.body,true); return true; }
	if (op == W8LiveStatusOperation::Channels) { W8LiveChannelSnapshot c; if (p.read_channel) p.read_channel(p.context,c); r.body=Channels(c); r.header=Header(r.body,false); return true; }
	W8LiveMeshSnapshot m; if (p.read_mesh) p.read_mesh(p.context,m); r.body=Mesh(m); r.header=Header(r.body,false); return true;
}

bool RunW8LiveStatusCharacterizationSelfTest(std::string& failure) {
	W8LiveStatusPort p; W8LiveStatusResponse r; W8LiveStatusSnapshot s; s.user_hash="0011"; s.connecting_client_count=1; s.connecting_client_adds=2; s.connecting_client_high_water=3; s.connecting_client_duplicate_adds=4;
	p.context=&s; p.read_status=[](void* x,W8LiveStatusSnapshot& y){y=*static_cast<W8LiveStatusSnapshot*>(x);return true;}; RunW8LiveStatusApi(W8LiveStatusOperation::Status,true,p,r);
	const std::string local="{\"upnp_critical_error\":false,\"utp_hole_punch_enabled\":false,\"web_upnp_active\":false,\"upnp_ports_forwarded\":\"unknown\",\"kad_connected\":false,\"kad_configured_mask\":0,\"kad_running_mask\":0,\"kad2_running\":false,\"kad2_connected\":false,\"kad6_running\":false,\"kad6_connected\":false,\"kad6_verified_contacts\":0,\"ed2k_connected\":false,\"user_hash\":\"0011\",\"connecting_client_count\":1,\"connecting_client_adds\":2,\"connecting_client_high_water\":3,\"connecting_client_duplicate_adds\":4,\"hole_punch_attempts\":0,\"hole_punch_success\":0,\"hole_punch_sym_nat_fail\":0,\"hole_punch_encrypted\":0,\"hole_punch_plaintext\":0,\"hole_punch_req_recv\":0,\"hole_punch_challenge_sent\":0,\"kad3_rdv_req_sent\":0,\"kad3_rdv_req_recv\":0,\"kad3_rdv_challenge_sent\":0,\"kad3_rdv_fwd\":0,\"kad3_rdv_success\":0,\"keepalive_running\":false,\"keepalive_pings_sent\":0,\"keepalive_pongs_recv\":0,\"keepalive_supernodes\":0,\"netlab_consent\":\"undecided\",\"netlab_advanced_consent\":\"undecided\",\"netlab_contribution_consent\":\"undecided\",\"netlab_enabled\":false}";
	const std::string localHeader="HTTP/1.1 200 OK\r\nServer: eMule\r\nConnection: close\r\nContent-Type: text/html\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: http://localhost:3000\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\nAccess-Control-Expose-Headers: X-CSRF-Token\r\nContent-Type: application/json\r\nContent-Length: "+std::to_string(local.size())+"\r\n\r\n"; if (r.body != local || r.header != localHeader) { failure="status local wire"; return false; }
	RunW8LiveStatusApi(W8LiveStatusOperation::Status,false,p,r); std::string remote=local; const std::string a="\"user_hash\":\"0011\",\"connecting_client_count\":1,\"connecting_client_adds\":2,\"connecting_client_high_water\":3,\"connecting_client_duplicate_adds\":4"; const std::string b="\"user_hash\":null,\"connecting_client_count\":null,\"connecting_client_adds\":null,\"connecting_client_high_water\":null,\"connecting_client_duplicate_adds\":null"; remote.replace(remote.find(a),a.size(),b); std::string remoteHeader=localHeader; const std::size_t remoteLengthAt=remoteHeader.find("Content-Length: ")+16, remoteLengthEnd=remoteHeader.find("\r\n",remoteLengthAt); remoteHeader.replace(remoteLengthAt,remoteLengthEnd-remoteLengthAt,std::to_string(remote.size())); if(r.body!=remote || r.header!=remoteHeader || r.body.find("0011")!=std::string::npos){failure="status remote privacy";return false;}
	ConcurrentStatus concurrent; concurrent.snapshots[0]=s; concurrent.snapshots[1]=s; concurrent.snapshots[1].user_hash="aabb"; concurrent.snapshots[1].connecting_client_count=-11; concurrent.snapshots[1].connecting_client_adds=22; concurrent.snapshots[1].connecting_client_high_water=33; concurrent.snapshots[1].connecting_client_duplicate_adds=-44;
	std::string alternate=local; const std::string alternateFields="\"user_hash\":\"aabb\",\"connecting_client_count\":-11,\"connecting_client_adds\":22,\"connecting_client_high_water\":33,\"connecting_client_duplicate_adds\":-44"; alternate.replace(alternate.find(a),a.size(),alternateFields); std::string alternateHeader=localHeader; const std::size_t lengthAt=alternateHeader.find("Content-Length: ")+16, lengthEnd=alternateHeader.find("\r\n",lengthAt); alternateHeader.replace(lengthAt,lengthEnd-lengthAt,std::to_string(alternate.size()));
	p.context=&concurrent; p.read_status=ReadConcurrentStatus; const W8LiveStatusPort concurrentPort=p; std::vector<W8LiveStatusResponse> responses(24); std::vector<std::thread> workers; workers.reserve(responses.size()); for(std::size_t i=0;i<responses.size();++i) workers.emplace_back([&concurrentPort,&responses,i]{RunW8LiveStatusApi(W8LiveStatusOperation::Status,true,concurrentPort,responses[i]);}); for(std::thread& worker:workers) worker.join();
	{ std::lock_guard<std::mutex> lock(concurrent.mutex); if(concurrent.calls!=responses.size()){failure="status concurrent calls";return false;} } for(const W8LiveStatusResponse& response:responses) if(!((response.body==local && response.header==localHeader)||(response.body==alternate && response.header==alternateHeader))){failure="status concurrent snapshot";return false;}
	W8LiveChannelSnapshot c; p.context=&c; p.read_channel=[](void* x,W8LiveChannelSnapshot& y){y=*static_cast<W8LiveChannelSnapshot*>(x);return true;}; RunW8LiveStatusApi(W8LiveStatusOperation::Channels,true,p,r); if(r.body!="{\"channels\":[]}" || r.header!="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 15\r\n\r\n"){failure="channels empty";return false;}
	const std::uint32_t rates[]={2999,3000,4999,5000,7999,8000}; const char* qualities[]={"SD","HD","HD","FHD","FHD","4K"}; c.broadcasting=true; c.stream_key[0]=0xab; c.stream_key[15]=0x10; c.title="\"\\\n\x01"; c.category="\t"; c.language="\r"; c.started_at=123; c.viewer_count=7;
	const std::string channelPrefix="{\"channels\":[{\"hash\":\"ab000000000000000000000000000010\",\"title\":\"\\\"\\\\\\n\\u0001\",\"category\":\"\\t\",\"language\":\"\\r\",\"startedAt\":123,\"viewers\":7,\"bitrate\":";
	for(unsigned i=0;i<6;++i){c.bitrate=rates[i];RunW8LiveStatusApi(W8LiveStatusOperation::Channels,true,p,r);const std::string wire=channelPrefix+std::to_string(rates[i])+",\"quality\":\""+qualities[i]+"\"}]}";const std::string header="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\nContent-Length: "+std::to_string(wire.size())+"\r\n\r\n";if(r.body!=wire || r.header!=header){failure="channels threshold";return false;}}
	W8LiveMeshSnapshot m; p.context=&m; p.read_mesh=[](void* x,W8LiveMeshSnapshot& y){y=*static_cast<W8LiveMeshSnapshot*>(x);return true;}; const std::string meshEmpty="{\"meshPeers\":0,\"pendingRequests\":0,\"chunksServed\":0,\"totalRedistributed\":0,\"trustLevels\":{\"superSeeders\":0,\"middle\":0,\"leaf\":0},\"uploadFloor\":0,\"emergencyMode\":false,\"source\":\"emule-core\"}"; RunW8LiveStatusApi(W8LiveStatusOperation::Mesh,true,p,r); if(r.body!=meshEmpty || r.header!="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 188\r\n\r\n"){failure="mesh empty";return false;}
	m.mesh_peers=1;m.pending_requests=2;m.chunks_served=3;m.total_redistributed=4;m.super_seeders=5;m.middle_peers=6;m.leaf_peers=7;m.upload_floor=8;m.emergency_mode=true; const std::string meshActive="{\"meshPeers\":1,\"pendingRequests\":2,\"chunksServed\":3,\"totalRedistributed\":4,\"trustLevels\":{\"superSeeders\":5,\"middle\":6,\"leaf\":7},\"uploadFloor\":8,\"emergencyMode\":true,\"source\":\"emule-core\"}"; RunW8LiveStatusApi(W8LiveStatusOperation::Mesh,true,p,r);if(r.body!=meshActive || r.header!="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 187\r\n\r\n"){failure="mesh active";return false;}
	failure.clear(); return true;
}

} } // namespace ese::web
