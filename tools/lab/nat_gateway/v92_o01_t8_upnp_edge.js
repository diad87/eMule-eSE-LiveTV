'use strict';
const http = require('node:http'); const dgram = require('node:dgram'); const net=require('node:net');
const { decodeUpnpMSearch, encodeUpnpMSearchResponse } = require('./upnp_ssdp_discovery');
const { encodeUpnpDeviceDescription, encodeUpnpServiceDescription } = require('./upnp_description_http');
const { decodeUpnpAddPortMapping, decodeUpnpDeletePortMapping, decodeUpnpPortMappingReadback, decodeUpnpSoapQuery, encodeUpnpSoapQueryResponse } = require('./upnp_soap_control');
const TARGET = 'urn:schemas-upnp-org:device:InternetGatewayDevice:1';
const UUID = 'uuid:92345678-1234-1234-1234-123456789abc';
function createO01UpnpEdge(config) {
  if (!config || !['NON_RELEASE','FORMAL_T8'].includes(config.mode) || typeof config.adapter?.applyUpnp !== 'function') throw new Error('O01_UPNP_EDGE_CONFIG_INVALID');
  const formal=config.mode==='FORMAL_T8';
  const dependencies=config.dependencies||{};
  if(formal&&Object.keys(dependencies).length)throw new Error('O01_UPNP_EDGE_FORMAL_DEPENDENCY_INVALID');
  if(Object.keys(dependencies).some(key=>!['bindSsdp','onHttpBound','listenWeb'].includes(key))||
     (dependencies.bindSsdp&&typeof dependencies.bindSsdp!=='function')||
     (dependencies.onHttpBound&&typeof dependencies.onHttpBound!=='function')||
     (dependencies.listenWeb&&typeof dependencies.listenWeb!=='function'))throw new Error('O01_UPNP_EDGE_DEPENDENCY_INVALID');
  if(formal){const p=config.provenance;if(!p||p.schema!=='ese.v92.t8-bind/v1'||p.adapter_address!==config.bind_address||!/^[a-f0-9]{64}$/.test(p.interface_id_digest||'')||!/^[a-f0-9]{64}$/.test(p.hyperv_switch_digest||'')||!Number.isInteger(p.http_port)||p.http_port<1||p.http_port>65535)throw new Error('O01_UPNP_EDGE_PROVENANCE_INVALID');}
  else if(config.bind_address!=='127.0.0.1')throw new Error('O01_UPNP_EDGE_CONFIG_INVALID');
  if(net.isIP(config.external_address)!==4||(formal&&config.external_address!=='88.11.22.4'))throw new Error('O01_UPNP_EDGE_EXTERNAL_ADDRESS_INVALID');
  const allowed=new Set(config.allowed_source_addresses||[]);if(!allowed.size||[...allowed].some(address=>net.isIP(address)!==4)||(formal&&[...allowed].some(address=>address.startsWith('127.'))))throw new Error('O01_UPNP_EDGE_SOURCES_INVALID');
  let web; let ssdp;
  const description = (port) => ({ adapter_address: formal?config.bind_address:'192.0.2.10', http_port: port, igd_version: 1, service_version: 1,
    udn_uuid: UUID, wan_device_uuid: 'uuid:22345678-1234-1234-1234-123456789abc', wan_connection_device_uuid: 'uuid:32345678-1234-1234-1234-123456789abc',
    cif_scpd_path: '/wancommonifcSCPD.xml', cif_control_path: '/control/WANCommonIFC1', cif_event_sub_path: null,
    scpd_path: '/wanipconnSCPD.xml', control_path: '/control/WANIPConn1', event_sub_path: '/event/WANIPConn1' });
  async function close(){const failures=[];if(ssdp){const current=ssdp;ssdp=null;try{await new Promise((resolve,reject)=>{try{current.close(resolve);}catch(error){if(error&&error.code==='ERR_SOCKET_DGRAM_NOT_RUNNING')resolve();else reject(error);}});}catch(error){failures.push(error);}}
    if(web){const current=web;web=null;try{await new Promise((resolve,reject)=>{if(!current.listening)return resolve();try{current.close(error=>error?reject(error):resolve());}catch(error){reject(error);}});}catch(error){failures.push(error);}}
    if(failures.length)throw new AggregateError(failures,'O01_UPNP_EDGE_CLOSE_FAILED');}
  return Object.freeze({ async start() {
   try{
    web = http.createServer((req, res) => {
      const remote=String(req.socket&&req.socket.remoteAddress||'');
      if(net.isIP(remote)!==4||!allowed.has(remote)){res.writeHead(403,{'connection':'close','content-length':'0'});return res.end();}
      if (req.method === 'GET' && req.url === '/rootDesc.xml') { const body = encodeUpnpDeviceDescription(description(web.address().port)); res.writeHead(200, {'content-type':'text/xml','content-length':body.length}); return res.end(body); }
      if (req.method !== 'POST' || req.url !== '/control/WANIPConn1') { res.writeHead(404); return res.end(); }
      const chunks=[]; let size=0; req.on('data',(c)=>{size+=c.length;if(size<=65536)chunks.push(c);}); req.on('end',()=>{ try {
        if(size>65536) throw new Error('oversize'); const action=String(req.headers.soapaction||''); const wire=Buffer.concat(chunks);
        const command=action.includes('#DeletePortMapping')?decodeUpnpDeletePortMapping(action,wire):action.includes('#GetSpecificPortMappingEntry')?decodeUpnpPortMappingReadback(action,wire):(action.includes('#GetExternalIPAddress')||action.includes('#GetStatusInfo'))?decodeUpnpSoapQuery(action,wire):decodeUpnpAddPortMapping(action,wire);
        const projected=command.operation==='get_external_ip_address'?{ok:true,external_address:config.external_address}:command.operation==='get_status_info'?{ok:true,connection_status:'Connected',last_connection_error:'ERROR_NONE',uptime_seconds:Math.max(0,config.adapter.observe().epoch)}:command.operation.startsWith('get_')?config.adapter.readUpnp(command):(()=>{const result=config.adapter.applyUpnp(command);return result.ok?{ok:true}:{ok:false,error_code:result.error_code,error_description:result.error_description};})();
        const framed=encodeUpnpSoapQueryResponse(command,projected);
        res.writeHead(framed.status_code,{'content-type':'text/xml','content-length':framed.body.length});res.end(framed.body);
      } catch(_){res.writeHead(400);res.end();} });
    });
    if(dependencies.listenWeb)await dependencies.listenWeb(web);
    else await new Promise((resolve,reject)=>{web.once('error',reject);web.listen(formal?config.provenance.http_port:0,config.bind_address,resolve);});
    if(dependencies.onHttpBound)dependencies.onHttpBound(web.address().port,web);
    ssdp=dgram.createSocket({type:'udp4',reuseAddr:true}); ssdp.on('message',(packet,peer)=>{if(!allowed.has(peer.address))return;try{const command=decodeUpnpMSearch(packet,{search_target:TARGET});const response=encodeUpnpMSearchResponse(command,{adapter_address:formal?config.bind_address:'192.0.2.10',http_port:web.address().port,description_path:'/rootDesc.xml',usn_uuid:UUID,max_age_seconds:1800});ssdp.send(response,peer.port,peer.address);}catch(_){}});
    if(dependencies.bindSsdp)await dependencies.bindSsdp(ssdp,formal?1900:0,config.bind_address);else await new Promise((resolve,reject)=>{ssdp.once('error',reject);ssdp.bind(formal?1900:0,formal?'0.0.0.0':config.bind_address,()=>{try{if(formal){ssdp.addMembership('239.255.255.250',config.bind_address);ssdp.setMulticastInterface(config.bind_address);}resolve();}catch(error){reject(error);}});});
    return Object.freeze({http:Object.freeze({address:config.bind_address,port:web.address().port}),ssdp:Object.freeze({address:config.bind_address,port:ssdp.address().port})});
   }catch(error){try{await close();}catch(cleanup){throw new AggregateError([error,cleanup],'O01_UPNP_EDGE_START_ROLLBACK_FAILED');}throw error;}
  }, close });
}
module.exports=Object.freeze({createO01UpnpEdge});
