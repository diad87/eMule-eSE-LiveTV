'use strict';
const { createGatewayAdapter } = require('./v92_o01_t8_gateway_adapter');
const { createO01UdpMux } = require('./v92_o01_t8_udp_mux');
const { createO01UpnpEdge } = require('./v92_o01_t8_upnp_edge');
const { createO01FaultController } = require('./v92_o01_t8_fault_controller');
const FAULTS=new Set(['renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary']);
async function createT8NetworkAdapter(options){
 if(!options||!['NON_RELEASE','FORMAL_T8'].includes(options.mode))throw new Error('O01_NETWORK_CONFIG_INVALID');
 // This exact test-only value is pinned by libnatmap's address-policy corpus
 // as IPv4 Public; it is never bound, routed or serialized by the bridge.
 const formalExternal='88.11.22.4';
 if(options.mode==='FORMAL_T8'&&options.externalAddress!==formalExternal)throw new Error('O01_NETWORK_EXTERNAL_ADDRESS_INVALID');
 const semantic=createGatewayAdapter({now:options.now,resources:options.resources,externalAddress:options.externalAddress});
 const faults=createO01FaultController(options.faultDependencies);
 const common={mode:options.mode,bind_address:options.bindAddress,external_address:options.externalAddress||'198.51.100.10',adapter:semantic,provenance:options.provenance,allowed_source_addresses:options.allowedSources||[options.bindAddress]};
 const mux=createO01UdpMux({...common,port:options.mode==='FORMAL_T8'?5351:0,allowed_source_addresses:options.allowedSources||[options.bindAddress],fault_controller:faults});
 const upnp=createO01UpnpEdge(common); let muxStarted=false,upnpStarted=false,closed=false;
 try{await mux.start();muxStarted=true;await upnp.start();upnpStarted=true;}catch(error){if(upnpStarted)await upnp.close();if(muxStarted)await mux.close();semantic.cleanupOwned();throw error;}
 return Object.freeze({
  async observe(){if(closed)throw new Error('O01_NETWORK_CLOSED');return semantic.observeProtocol();},
  async inject(fault){if(closed||!FAULTS.has(fault))throw new Error('O01_NETWORK_FAULT_INVALID');
   if(['dropped_late','explicit_reject','stale','replay_duplicate','malformed','partial_pair','final_boundary'].includes(fault)){faults.arm(fault);return semantic.observeProtocol();}
   const generation=semantic.observe().generation;
   if(fault==='renew_success'){for(const protocol of ['pcp','natpmp','upnp'])if(semantic.observe().mappings.some(x=>x.protocol===protocol&&x.client_id==='o01-client'))semantic.renewPair(protocol);}
   else if(fault==='expiry')semantic.expire();
   else if(fault==='epoch_reset'||fault==='dropped_late')semantic.restartEpoch(semantic.observe().epoch+1);
   else if(['stale','replay_duplicate','malformed','explicit_reject'].includes(fault))semantic.rejectStale(generation+1);
   else { semantic.cleanupOwned(); }
   return semantic.observeProtocol();},
  async shutdown(){if(closed)return semantic.observeProtocol();closed=true;const failures=[];try{await upnp.close();}catch(e){failures.push(e);}try{await mux.close();}catch(e){failures.push(e);}const final=semantic.cleanupOwned();if(failures.length)throw new AggregateError(failures,'O01_NETWORK_CLOSE_FAILED');return final;}
 });
}
module.exports=Object.freeze({createT8NetworkAdapter});
