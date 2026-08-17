'use strict';
const { createGatewayAdapter } = require('./v92_o01_t8_gateway_adapter');
const { createO01UdpMux } = require('./v92_o01_t8_udp_mux');
const { createO01UpnpEdge } = require('./v92_o01_t8_upnp_edge');
const { createO01FaultController } = require('./v92_o01_t8_fault_controller');
const FAULTS=new Set(['renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary']);
const FORMAL_GRANTED_LIFETIME_SECONDS=120;
const FORMAL_LATE_DELAY_MS=8000;
function projectObservation(semanticProjection,faultProjection){
 const gateway=Object.freeze({...semanticProjection.gateway,last_fault:faultProjection.last_executed_fault_name});
 return Object.freeze({...semanticProjection,gateway,faults:faultProjection});
}
async function createT8NetworkAdapter(options){
 if(!options||!['NON_RELEASE','FORMAL_T8'].includes(options.mode))throw new Error('O01_NETWORK_CONFIG_INVALID');
 // This exact test-only value is pinned by libnatmap's address-policy corpus
 // as IPv4 Public; it is never bound, routed or serialized by the bridge.
 const formalExternal='88.11.22.4';
 if(options.mode==='FORMAL_T8'&&options.externalAddress!==formalExternal)throw new Error('O01_NETWORK_EXTERNAL_ADDRESS_INVALID');
 const formal=options.mode==='FORMAL_T8';
 const maximumLifetimeSeconds=options.maximumLifetimeSeconds===undefined&&!formal?FORMAL_GRANTED_LIFETIME_SECONDS:options.maximumLifetimeSeconds;
 const lateDelayMs=options.lateDelayMs===undefined&&!formal?FORMAL_LATE_DELAY_MS:options.lateDelayMs;
 if(formal&&(typeof options.now!=='function'||maximumLifetimeSeconds!==FORMAL_GRANTED_LIFETIME_SECONDS||lateDelayMs!==FORMAL_LATE_DELAY_MS))throw new Error('O01_NETWORK_FORMAL_TIMING_INVALID');
 const semantic=createGatewayAdapter({now:options.now,resources:options.resources,externalAddress:options.externalAddress,maximumLifetimeSeconds});
 const faults=createO01FaultController({...options.faultDependencies,lateDelayMs});
 const common={mode:options.mode,bind_address:options.bindAddress,external_address:options.externalAddress||'198.51.100.10',adapter:semantic,provenance:options.provenance,allowed_source_addresses:options.allowedSources||[options.bindAddress]};
 const mux=createO01UdpMux({...common,port:options.mode==='FORMAL_T8'?5351:0,allowed_source_addresses:options.allowedSources||[options.bindAddress],fault_controller:faults});
 const upnp=createO01UpnpEdge(common); let muxStarted=false,upnpStarted=false,closed=false;
 let legacyOrdinal=0;
 const project=()=>{
  const semanticProjection=semantic.observeProtocol();
  const faultProjection=faults.state();
  return projectObservation(semanticProjection,faultProjection);
 };
 try{await mux.start();muxStarted=true;await upnp.start();upnpStarted=true;}catch(error){if(upnpStarted)await upnp.close();if(muxStarted)await mux.close();semantic.cleanupOwned();throw error;}
 return Object.freeze({
  async observe(){if(closed)throw new Error('O01_NETWORK_CLOSED');return project();},
  async beginSlot(fault,ordinal){if(closed||!FAULTS.has(fault)||!Number.isSafeInteger(ordinal)||ordinal<1)throw new Error('O01_NETWORK_FAULT_INVALID');
   faults.arm(fault,{planned_ordinal:ordinal});
   return project();},
  async inject(fault){if(closed||!FAULTS.has(fault))throw new Error('O01_NETWORK_FAULT_INVALID');
   legacyOrdinal++;faults.arm(fault,{planned_ordinal:legacyOrdinal});return project();},
  async shutdown(){if(closed)return project();closed=true;const failures=[];try{await upnp.close();}catch(e){failures.push(e);}try{await mux.close();}catch(e){failures.push(e);}semantic.cleanupOwned();const final=project();if(failures.length)throw new AggregateError(failures,'O01_NETWORK_CLOSE_FAILED');return final;}
});
}
module.exports=Object.freeze({createT8NetworkAdapter,FORMAL_GRANTED_LIFETIME_SECONDS,FORMAL_LATE_DELAY_MS,
 _projectObservationForTest:projectObservation});
