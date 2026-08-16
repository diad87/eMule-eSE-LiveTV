'use strict';

const fs=require('node:fs');const path=require('node:path');
const{createT8Child}=require('./v92_o01_t8_child');
const{runFormalController}=require('./v92_o01_formal_controller');
const{createFormalRpc}=require('./v92_o01_formal_rpc');

function exactKeys(value,expected){return value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...expected].sort().join(',');}
function regularLocalFile(file){const stat=fs.lstatSync(file);return stat.isFile()&&!stat.isSymbolicLink();}
function readConfig(file){const resolved=path.resolve(file);if(!regularLocalFile(resolved)||fs.statSync(resolved).size>16384)throw new Error('O01_HOST_CONFIG_INVALID');let value;try{value=JSON.parse(fs.readFileSync(resolved,'utf8'));}catch(_){throw new Error('O01_HOST_CONFIG_INVALID');}
 if(!exactKeys(value,['schema','repo_root','evidence_root','child'])||value.schema!=='ese.v92.o01-formal-host-config/v1'||typeof value.repo_root!=='string'||typeof value.evidence_root!=='string'||
   !exactKeys(value.child,['mode','bindAddress','allowedSource','interfaceSha256','switchSha256','httpPort','externalAddress'])||value.child.mode!=='FORMAL_T8')throw new Error('O01_HOST_CONFIG_INVALID');
 const repo=path.resolve(value.repo_root),evidence=path.resolve(value.evidence_root);if(!fs.statSync(repo).isDirectory()||!fs.statSync(evidence).isDirectory()||fs.readdirSync(evidence).length!==1||path.dirname(resolved)!==evidence)throw new Error('O01_HOST_CONFIG_INVALID');
 return Object.freeze({repoRoot:repo,evidenceRoot:evidence,child:Object.freeze({...value.child})});}
function writeExclusive(file,value){const body=`${JSON.stringify(value,null,2)}\n`;const handle=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(handle,body,'utf8');fs.fsyncSync(handle);}finally{fs.closeSync(handle);}}
async function main(){if(process.argv.length!==3||Number(process.versions.node.split('.')[0])!==22)throw new Error('O01_HOST_AUTHORITY');const config=readConfig(process.argv[2]);const scenario=JSON.parse(fs.readFileSync(path.join(config.repoRoot,'tools/lab/nat_gateway/v92_o01_scenario.json'),'utf8'));const rpc=createFormalRpc({input:process.stdin,output:process.stdout});
 try{const result=await runFormalController({config:scenario,repoRoot:config.repoRoot,child:createT8Child(config.child),readProduct:()=>rpc.requestProduct(),emitCheckpoint:async(record)=>{const ordinal=String(record.ordinal).padStart(2,'0');writeExclusive(path.join(config.evidenceRoot,`checkpoint-${ordinal}.json`),record);return record.record_sha256;}});writeExclusive(path.join(config.evidenceRoot,'controller-result.json'),result);}finally{rpc.close();}}
if(require.main===module)main().catch(error=>{process.stderr.write(`V92_O01_FORMAL_HOST_FAIL ${error.message}\n`);process.exitCode=1;});
module.exports=Object.freeze({readConfig,writeExclusive});
