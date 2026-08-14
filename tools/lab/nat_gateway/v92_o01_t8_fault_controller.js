'use strict';
const { createNatPmpFaultInjector } = require('./natpmp_fault_injector');
const NAMES=new Set(['renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary']);
function createO01FaultController(dependencies={}){
 const sleep=dependencies.sleep||((ms,signal)=>new Promise((resolve,reject)=>{const id=setTimeout(resolve,ms);signal.addEventListener('abort',()=>{clearTimeout(id);reject(new Error('aborted'));},{once:true});}));
 let armed=null,captured=null,ordinal=0;
 return Object.freeze({arm(name,options={}){if(armed||!NAMES.has(name))throw new Error('O01_FAULT_ARM_INVALID');armed={name,deadline_ms:options.deadline_ms||100,epoch:options.epoch||77};},
  async apply(packet,command,signal){if(!Buffer.isBuffer(packet)||!(signal instanceof AbortSignal))throw new Error('O01_FAULT_INPUT_INVALID');ordinal++;
   const fault=armed;armed=null;if(!fault){captured=Buffer.from(packet);return Object.freeze({packets:Object.freeze([Buffer.from(packet)]),fault:'renew_success',ordinal,commit:true});}
   if(fault.name==='renew_success'||fault.name==='expiry'){captured=Buffer.from(packet);return Object.freeze({packets:Object.freeze([Buffer.from(packet)]),fault:fault.name,ordinal,commit:true});}
   if(fault.name==='partial_pair'&&command.transport!=='udp')throw new Error('O01_FAULT_PARTIAL_REQUIRES_UDP');
   if(fault.name==='replay_duplicate'){if(!captured)throw new Error('O01_FAULT_REPLAY_EMPTY');return Object.freeze({packets:Object.freeze([Buffer.from(captured),Buffer.from(captured)]),fault:fault.name,ordinal,commit:false});}
   if(command.protocol==='natpmp'){
    let action=fault.name==='dropped_late'?{type:'delay',delay_ms:fault.deadline_ms+1,jitter_ms:0}:fault.name==='explicit_reject'||fault.name==='stale'?{type:'reject',result_code:'not-authorized'}:fault.name==='epoch_reset'?{type:'restart-gateway',restart_epoch_seconds:fault.epoch}:fault.name==='malformed'?{type:'truncate',length_bytes:3}:{type:'drop'};
    const out=await createNatPmpFaultInjector(action,{sleep})(packet,command,signal);if(fault.name==='dropped_late'&&out)captured=Buffer.from(out);return Object.freeze({packets:Object.freeze(out?[Buffer.from(out)]:[]),fault:fault.name,ordinal,late:fault.name==='dropped_late',commit:false});
   }
   if(fault.name==='dropped_late')await sleep(fault.deadline_ms+1,signal);
   if(['explicit_reject','stale'].includes(fault.name)){const out=Buffer.from(packet);out[3]=2;out.fill(0,12,24);return Object.freeze({packets:Object.freeze([out]),fault:fault.name,ordinal,commit:false});}
   if(fault.name==='malformed')return Object.freeze({packets:Object.freeze([Buffer.from(packet.subarray(0,3))]),fault:fault.name,ordinal,commit:false});
   return Object.freeze({packets:Object.freeze([]),fault:fault.name,ordinal,late:fault.name==='dropped_late',commit:false});
  },state(){return Object.freeze({armed:armed?armed.name:null,captured:captured!==null,ordinal});}});
}
module.exports=Object.freeze({createO01FaultController});
