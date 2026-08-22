'use strict';

const fs=require('node:fs');const path=require('node:path');
const{createT8Child}=require('./v92_o01_t8_child');
const{runFormalController}=require('./v92_o01_formal_controller');
const{createFormalRpc}=require('./v92_o01_formal_rpc');

const CLOCK_FAILURE_CODES=new Set(['O01_CONTROLLER_CLOCK_INVALID','O01_CONTROLLER_CLOCK_NONMONOTONIC',
 'O01_CONTROLLER_CLOCK_CHECKPOINT_GAP','O01_CONTROLLER_CLOCK_INTERTICK_GAP']);
const CLOCK_FAILURE_STAGES=new Set(['EPOCH','TARGET','AFTER_PREFLIGHT','AFTER_BEGIN_SLOT','AFTER_OBSERVE',
 'AFTER_PRODUCT','AFTER_CHECKPOINT','AFTER_SLEEP','TIMING_GATE']);

function exactKeys(value,expected){return value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...expected].sort().join(',');}
function regularLocalFile(file){const stat=fs.lstatSync(file);return stat.isFile()&&!stat.isSymbolicLink();}
function readConfig(file){const resolved=path.resolve(file);if(!regularLocalFile(resolved)||fs.statSync(resolved).size>16384)throw new Error('O01_HOST_CONFIG_INVALID');let value;try{value=JSON.parse(fs.readFileSync(resolved,'utf8'));}catch(_){throw new Error('O01_HOST_CONFIG_INVALID');}
 if(!exactKeys(value,['schema','repo_root','evidence_root','child'])||value.schema!=='ese.v92.o01-formal-host-config/v1'||typeof value.repo_root!=='string'||typeof value.evidence_root!=='string'||
   !exactKeys(value.child,['mode','bindAddress','allowedSource','interfaceSha256','switchSha256','httpPort','externalAddress'])||value.child.mode!=='FORMAL_T8')throw new Error('O01_HOST_CONFIG_INVALID');
 const repo=path.resolve(value.repo_root),evidence=path.resolve(value.evidence_root);if(!fs.statSync(repo).isDirectory()||!fs.statSync(evidence).isDirectory()||fs.readdirSync(evidence).length!==1||path.dirname(resolved)!==evidence)throw new Error('O01_HOST_CONFIG_INVALID');
 return Object.freeze({repoRoot:repo,evidenceRoot:evidence,child:Object.freeze({...value.child})});}
function writeExclusive(file,value){const body=`${JSON.stringify(value,null,2)}\n`;const handle=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(handle,body,'utf8');fs.fsyncSync(handle);}finally{fs.closeSync(handle);}}
function publishClockFailure(evidenceRoot,error){const value=error&&error.clockFailure;if(!value)return false;
 const integerOrNull=(candidate)=>candidate===null||Number.isSafeInteger(candidate);
 if(error.message!==value.code||!exactKeys(value,['schema','code','tick','slot','target','elapsed','last_tick','lateness','checkpoint_shift','limits','stage'])||
   value.schema!=='ese.v92.o01-clock-failure/v1'||!CLOCK_FAILURE_CODES.has(value.code)||!CLOCK_FAILURE_STAGES.has(value.stage)||
   !Number.isSafeInteger(value.tick)||value.tick<0||value.tick>2880||!Number.isSafeInteger(value.slot)||value.slot<0||value.slot>96||
   !integerOrNull(value.target)||!integerOrNull(value.elapsed)||!Number.isSafeInteger(value.last_tick)||value.last_tick<0||
   !integerOrNull(value.lateness)||!Number.isSafeInteger(value.checkpoint_shift)||value.checkpoint_shift<0||
   !exactKeys(value.limits,['tick_ms','checkpoint_ms','checkpoint_max_gap_ms','checkpoint_shift_limit_ms','intertick_gap_limit_ms'])||
   value.limits.tick_ms!==10000||value.limits.checkpoint_ms!==300000||value.limits.checkpoint_max_gap_ms!==370000||
   value.limits.checkpoint_shift_limit_ms!==70000||value.limits.intertick_gap_limit_ms!==80000)throw new Error('O01_HOST_CLOCK_FAILURE_INVALID');
 const root=path.resolve(evidenceRoot);if(!fs.statSync(root).isDirectory())throw new Error('O01_HOST_CLOCK_FAILURE_INVALID');
 writeExclusive(path.join(root,'clock-failure.json'),value);return true;}
async function main(){if(process.argv.length!==3||Number(process.versions.node.split('.')[0])!==22)throw new Error('O01_HOST_AUTHORITY');const config=readConfig(process.argv[2]);const scenario=JSON.parse(fs.readFileSync(path.join(config.repoRoot,'tools/lab/nat_gateway/v92_o01_scenario.json'),'utf8'));const rpc=createFormalRpc({input:process.stdin,output:process.stdout});
 try{try{const result=await runFormalController({config:scenario,repoRoot:config.repoRoot,child:createT8Child(config.child),readProduct:()=>rpc.requestProduct(),emitCheckpoint:async(record)=>{const ordinal=String(record.ordinal).padStart(2,'0');writeExclusive(path.join(config.evidenceRoot,`checkpoint-${ordinal}.json`),record);return record.record_sha256;}});writeExclusive(path.join(config.evidenceRoot,'controller-result.json'),result);}catch(error){publishClockFailure(config.evidenceRoot,error);throw error;}}finally{rpc.close();}}
if(require.main===module)main().catch(error=>{process.stderr.write(`V92_O01_FORMAL_HOST_FAIL ${error.message}\n`);process.exitCode=1;});
module.exports=Object.freeze({readConfig,writeExclusive,publishClockFailure});
