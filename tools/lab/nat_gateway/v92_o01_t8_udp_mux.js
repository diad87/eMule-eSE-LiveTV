'use strict';
const dgram = require('node:dgram');
const net = require('node:net');
const { decodeNatPmpRequest } = require('./natpmp_request_decoder');
const { encodeNatPmpResponse } = require('./natpmp_response_encoder');
const { decodePcpMapRequest } = require('./pcp_map_request_decoder');
const { encodePcpMapResponse } = require('./pcp_map_response_encoder');
const { decodePcpAnnounceRequest, encodePcpAnnounceResponse } = require('./pcp_announce_codec');

function createO01UdpMux(config) {
  if (!config || !['NON_RELEASE','FORMAL_T8'].includes(config.mode) || typeof config.adapter?.observe !== 'function' ||
      typeof config.adapter?.mapPair !== 'function' || typeof config.adapter?.renewPair !== 'function' ||
      typeof config.adapter?.recordWireOutcome !== 'function') throw new Error('O01_MUX_CONFIG_INVALID');
  if (config.fault_controller && (typeof config.fault_controller.apply !== 'function' ||
      typeof config.fault_controller.claimBoundary !== 'function' ||
      typeof config.fault_controller.recordBoundary !== 'function' ||
      typeof config.fault_controller.recordTransaction !== 'function' ||
      typeof config.adapter.observeProtocol !== 'function' ||
      typeof config.adapter.applyFaultBoundary !== 'function')) throw new Error('O01_MUX_FAULT_CONFIG_INVALID');
  const formal = config.mode === 'FORMAL_T8';
  if (formal) {
    const p = config.provenance;
    if (!p || p.schema !== 'ese.v92.t8-bind/v1' || p.adapter_address !== config.bind_address ||
        !/^[a-f0-9]{64}$/.test(p.interface_id_digest || '') || !/^[a-f0-9]{64}$/.test(p.hyperv_switch_digest || '') ||
        net.isIP(config.bind_address) === 0 || net.isIP(config.bind_address) === 4 && config.bind_address.startsWith('127.') || config.port !== 5351) {
      throw new Error('O01_MUX_FORMAL_PROVENANCE_INVALID');
    }
  } else if (config.bind_address !== '127.0.0.1' || config.port !== 0) throw new Error('O01_MUX_NON_RELEASE_LOOPBACK_ONLY');
  const allowed = new Set(config.allowed_source_addresses || []);
  if (!allowed.size || [...allowed].some((entry) => net.isIP(entry) === 0)) throw new Error('O01_MUX_SOURCES_INVALID');
  let socket; let running = false;
  function natpmp(packet, peer) {
    const command = decodeNatPmpRequest(packet);
    if(command.operation==='external-address')return { command, boundary_identity:peer.address, response: encodeNatPmpResponse(config.adapter.applyNatPmp(command,peer.address)), token:null };
    return { command, boundary_identity:peer.address, prepare:()=>{const prepared=config.adapter.prepareNatPmp(command,peer.address);
      return { response:encodeNatPmpResponse(prepared.response),token:prepared.token,accepted:prepared.response.result_code===0 };} };
  }
  function pcp(packet, peer) {
    if (packet[1] === 0) {
      decodePcpAnnounceRequest(packet);
      return { command: Object.freeze({protocol:'pcp',operation:'announce',transport:null}), boundary_identity:peer.address, response: encodePcpAnnounceResponse({ mode: 'semantic', response_type: 'announce', result_code: 0, epoch: config.adapter.observe().epoch }) };
    }
    const command = decodePcpMapRequest(packet);
    return { command, boundary_identity:peer.address, prepare:()=>{const prepared=config.adapter.preparePcp(command,packet);
      return { response:encodePcpMapResponse(prepared.response),token:prepared.token,accepted:prepared.response.result_code===0 };} };
  }
  async function onMessage(packet, peer) {
    if (!running || !Buffer.isBuffer(packet) || packet.length < 2 || packet.length > 1100 || !allowed.has(peer.address)) return;
    let framed; let boundaryContext = null;
    try { framed = packet[0] === 0 ? natpmp(packet, peer) : packet[0] === 2 ? pcp(packet, peer) : null;
      if(framed&&framed.prepare){let prepared=framed.prepare();if(config.fault_controller&&prepared.accepted===true){const boundary=config.fault_controller.claimBoundary(framed.command,framed.boundary_identity);if(boundary){config.adapter.abortPrepared(prepared.token);boundaryContext={token:boundary,before:config.adapter.observeProtocol()};config.adapter.applyFaultBoundary(boundary.name);prepared=framed.prepare();}}
        framed={...framed,...prepared};}
      if(framed&&framed.token&&config.fault_controller&&framed.accepted!==false){const before=config.adapter.observeProtocol();const decision=await config.fault_controller.apply(framed.response,framed.command,new AbortController().signal,framed.boundary_identity);framed={...framed,responses:decision.packets,commit:decision.commit,decision,before};}
      else if(framed)framed={...framed,commit:true};
      if(framed&&framed.token){const pairCommitted=framed.commit?config.adapter.commitPrepared(framed.token):(config.adapter.abortPrepared(framed.token),false);if(boundaryContext&&framed.accepted===true){if(framed.commit!==true||pairCommitted!==false)throw new Error('O01_MUX_BOUNDARY_COMMIT_INVALID');config.fault_controller.recordBoundary(boundaryContext.token,boundaryContext.before,config.adapter.observeProtocol(),pairCommitted);}if(config.fault_controller&&framed.decision){const pairMember=framed.command.operation==='map'&&['tcp','udp'].includes(framed.command.transport);config.fault_controller.recordTransaction(framed.decision,Boolean(pairCommitted),framed.before,config.adapter.observeProtocol(),framed.command.protocol,pairMember);}}
      if(framed&&['pcp','natpmp'].includes(framed.command.protocol))config.adapter.recordWireOutcome(framed.command.protocol,Boolean(framed.commit&&framed.accepted!==false));
    } catch (_) { if(framed&&framed.token)config.adapter.abortPrepared(framed.token);return; }
    if (!framed||!running)return;for(const response of framed.responses||[framed.response])socket.send(response, peer.port, peer.address, () => {});
  }
  return Object.freeze({
    start() {
      if (running || socket) return Promise.reject(new Error('O01_MUX_STATE_INVALID'));
      socket = dgram.createSocket(net.isIP(config.bind_address) === 6 ? 'udp6' : 'udp4'); socket.on('message', (packet,peer)=>{void onMessage(packet,peer);});
      return new Promise((resolve, reject) => { socket.once('error', reject); socket.bind(config.port, config.bind_address, () => {
        socket.removeListener('error', reject); running = true; const value = socket.address(); resolve(Object.freeze({ address: value.address, port: value.port }));
      }); });
    },
    close() { if (!socket) return Promise.resolve(); running = false; return new Promise((resolve) => socket.close(() => { socket = null; resolve(); })); },
  });
}
module.exports = Object.freeze({ createO01UdpMux });
