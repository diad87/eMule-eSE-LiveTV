from __future__ import annotations
import argparse, hashlib, json, re, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
DOC='docs/architecture/v92_o01_governance_amendment_v1.json';DOC_PATH=ROOT/DOC
BASE='1ea8d9506c93ed5972cf6f370c2a06f4da1f74fc';HEX40=re.compile(r'^[0-9a-f]{40}$');HEX64=re.compile(r'^[0-9a-f]{64}$')
GOV=[DOC,'tools/architecture/verify_v92_o01_governance_amendment.py','tools/architecture/test_verify_v92_o01_governance_amendment.py']
H_PATHS=['artifacts/v92-o01-governance/activation.json','artifacts/v92-o01-governance/offline-summary.json','artifacts/v92-o01-governance/review-sol.json','artifacts/v92-o01-governance/review-terra.json']
S_PATHS=['artifacts/v92-o01-governance/nonrelease-smoke-raw.json','artifacts/v92-o01-governance/nonrelease-smoke-summary.json']
REVIEWS=['Terra APPROVE with no P0/P1','Sol APPROVE with no P0/P1']
GATES=['Node 22 complete nat_gateway suite','formal controller/validator/host/RPC focal suite','PowerShell parser for every changed ps1/psm1','product formal-soak mock','VM session rollback mock','formal RPC pump mock','formal runner source/mock gate','git diff --check']
OFFLINE=[
('Node 22 complete nat_gateway suite','npm.cmd test','O01_NODE_SUITE_PASS'),('formal controller/validator/host/RPC focal suite','node --test test/v92_o01_formal_controller.test.js test/v92_o01_validate_formal.test.js test/v92_o01_formal_host.test.js test/v92_o01_formal_rpc.test.js','O01_FORMAL_FOCAL_PASS'),('PowerShell parser for every changed ps1/psm1','powershell parser changed ps1/psm1','O01_POWERSHELL_PARSE_PASS'),('product formal-soak mock','powershell -File tools/lab/handoff93/test_product_mapper_formal_soak_mock.ps1','O01_PRODUCT_MOCK_PASS'),('VM session rollback mock','powershell -File tools/lab/test_v92_o01_vm_session_mock.ps1','O01_SESSION_MOCK_PASS'),('formal RPC pump mock','powershell -File tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1','O01_RPC_MOCK_PASS'),('formal runner source/mock gate','powershell -File tools/lab/test_v92_o01_formal_runner_mock.ps1','O01_RUNNER_MOCK_PASS'),('git diff --check','git diff --check','O01_DIFF_CHECK_PASS')]
STOPS=['functional path 37 or any path outside tools/lab','budget differs by one line','production source, project file or binary changes','unbound formal runner/helper appears','credential serialized to argv, environment, JSON or evidence','cleanup cannot prove exact owned firewall/VHD/VM/NIC authority','source, Node, package or evidence binding changes during a run','P0 or P1 review finding','release_gate=true before independent validation and exact baseline restoration']
class GateError(RuntimeError):pass
def sh(*args):return subprocess.run(args,cwd=ROOT,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout.decode().strip()
def git(*args):return sh('git',*args)
def exact(v,keys,w):
 if not isinstance(v,dict)or set(v)!=set(keys):raise GateError(f'{w} schema')
 return v
def sha(data):return hashlib.sha256(data).hexdigest()
def blob(commit,path):return subprocess.run(['git','show',f'{commit}:{path}'],cwd=ROOT,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
def load_bytes(data):return json.loads(data.decode('utf-8'))
def load():return json.loads(DOC_PATH.read_text(encoding='utf-8'))
def parents(commit):return git('show','-s','--format=%P',commit).split()
def changed(parent,commit):return sorted(filter(None,git('diff','--name-only',parent,commit,'--').splitlines()))
def commit_budget(parent,commit):
 rows=[]
 for line in git('diff','--numstat',parent,commit,'--').splitlines():
  a,d,p=line.split('\t',2)
  if not a.isdigit()or not d.isdigit():raise GateError('A binary payload')
  rows.append((p,int(a),int(d)))
 add=sum(x for _,x,_ in rows);delete=sum(x for *_,x in rows)
 if(len(rows),add,delete,add-delete)!=(36,1237,63,1174):raise GateError('A budget')
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def functional_paths():return [
'tools/lab/handoff93/run_product_mapper_cycle.ps1','tools/lab/handoff93/test_product_mapper_formal_soak_mock.ps1','tools/lab/nat_gateway/test/v92_o01_bridge_protocol.test.js','tools/lab/nat_gateway/test/v92_o01_formal_controller.test.js','tools/lab/nat_gateway/test/v92_o01_formal_host.test.js','tools/lab/nat_gateway/test/v92_o01_formal_rpc.test.js','tools/lab/nat_gateway/test/v92_o01_formal_rpc_peer_mock.js','tools/lab/nat_gateway/test/v92_o01_product_stream.test.js','tools/lab/nat_gateway/test/v92_o01_soak.test.js','tools/lab/nat_gateway/test/v92_o01_t8_child.test.js','tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js','tools/lab/nat_gateway/test/v92_o01_t8_fault_controller.test.js','tools/lab/nat_gateway/test/v92_o01_t8_gateway_adapter.test.js','tools/lab/nat_gateway/test/v92_o01_t8_network_adapter.test.js','tools/lab/nat_gateway/test/v92_o01_t8_udp_mux.test.js','tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js','tools/lab/nat_gateway/v92_o01_bridge_protocol.js','tools/lab/nat_gateway/v92_o01_formal_controller.js','tools/lab/nat_gateway/v92_o01_formal_host.js','tools/lab/nat_gateway/v92_o01_formal_rpc.js','tools/lab/nat_gateway/v92_o01_product_stream.js','tools/lab/nat_gateway/v92_o01_scenario.json','tools/lab/nat_gateway/v92_o01_soak.js','tools/lab/nat_gateway/v92_o01_t8_child.js','tools/lab/nat_gateway/v92_o01_t8_daemon.js','tools/lab/nat_gateway/v92_o01_t8_fault_controller.js','tools/lab/nat_gateway/v92_o01_t8_gateway_adapter.js','tools/lab/nat_gateway/v92_o01_t8_network_adapter.js','tools/lab/nat_gateway/v92_o01_t8_udp_mux.js','tools/lab/nat_gateway/v92_o01_validate_formal.js','tools/lab/run_v92_o01_formal.ps1','tools/lab/test_v92_o01_formal_rpc_pump_mock.ps1','tools/lab/test_v92_o01_formal_runner_mock.ps1','tools/lab/test_v92_o01_vm_session_mock.ps1','tools/lab/test_v92_o01_vm_t8_smoke.ps1','tools/lab/v92_o01_vm_session.psm1']
def validate(v):
 exact(v,{'schema','status','base_commit','scope','historical_governance_immutable','topology','phase_contract','governance_paths','functional_paths','carrier_paths','budget','excluded_state','required_reviews','offline_gates','physical_policy','stop_conditions','activation_state'},'root')
 if v['schema']!='ese.v92.o01-governance-amendment/v1'or v['status']!='DRAFT_PRE_G'or v['base_commit']!=BASE:raise GateError('identity')
 if v['scope']!='V92-O01 laboratory gateway, formal controller, product observation stream and isolated Hyper-V T8 runner only; no product binary or protocol production source.':raise GateError('scope')
 if v['historical_governance_immutable']!=['docs/architecture/mod52_migration_contract_v2.json','docs/architecture/mod52_migration_matrix_v2.json','docs/architecture/mod52_migration_activation_ledger_v1.json']:raise GateError('history')
 topo={'G':'direct child of base_commit; amendment, verifier and verifier test only','A':'direct child of G; exactly functional_paths and exact budget','H':'direct child of A; Terra and Sol APPROVE attestations plus offline gate summary; zero functional drift','S':'optional direct child of H; one elevated short smoke with release_gate=false; never release evidence','R':'direct child of H or S; archives one uninterrupted formal eight-hour run whose source_commit and source_tree are exactly A, plus separate H and optional S governance bindings; zero functional drift'}
 if v['topology']!=topo or v['governance_paths']!=GOV or v['functional_paths']!=functional_paths():raise GateError('closed paths/topology')
 phases={'schema':'ese.v92.o01-governance-phases/v1','merge_policy':'Every G/A/H/S/R commit has exactly one parent; merge, squash, rebase substitution and intermediate commits are rejected.','G':{'parent':'base_commit','delta':'governance_paths','artifacts':[]},'A':{'parent':'G','delta':'functional_paths','artifacts':[]},'H':{'parent':'A','delta':'h_carrier_paths','artifacts':['activation','offline_summary','review_terra','review_sol']},'S':{'optional':True,'parent':'H','delta':'s_carrier_paths','release_gate':False,'artifacts':['nonrelease_raw','nonrelease_summary']},'R':{'parent':'H_or_S','source':'A','governance':'H_and_optional_S','delta':'r_carrier_policy','release_gate':True,'artifacts':['checkpoints_01_95','controller_result','formal_validation','formal_run_result']}}
 carriers={'H':H_PATHS,'S':S_PATHS,'R':{'directory':'artifacts/v92-o01-formal','checkpoint_pattern':'checkpoint-(01..95).json','fixed':['controller-result.json','formal-run-result.json','formal-validation.json'],'file_count':98}}
 if v['phase_contract']!=phases or v['carrier_paths']!=carriers:raise GateError('phase contract')
 if v['budget']!={'path_count':36,'add_exact':1237,'delete_exact':63,'net_exact':1174,'headroom':0}or v['excluded_state']!=[{'path':'libutp','reason':'pre-existing submodule worktree state; not part of O01 and must not be staged'}]:raise GateError('budget/exclusion')
 if v['required_reviews']!=REVIEWS or v['offline_gates']!=GATES or v['stop_conditions']!=STOPS:raise GateError('normative lists')
 if v['physical_policy']!={'short_smoke':'NON_RELEASE only; release_gate must be false; absence of elevation is BLOCKED without mutation','formal':'exactly 28800000 monotonic milliseconds, no duration override, no resume, no skip-cleanup, Node 22, clean source tree','claim_rule':'No physical or release PASS may be claimed from mocks, a non-elevated attempt, or the short smoke.'}:raise GateError('physical policy')
 if v['activation_state']!={'G':None,'A':None,'H':None,'S':None,'R':None,'rule':'This draft never stores its own commit. Commit identities are derived from Git parents and recorded only by a later phase.'}:raise GateError('self reference')
 return True
def worktree_stats(v):
 stats={}
 for line in git('diff','HEAD','--numstat','--').splitlines():
  a,d,p=line.split('\t',2)
  if not a.isdigit()or not d.isdigit():raise GateError('binary payload')
  if p in GOV:continue
  stats[p]=(int(a),int(d))
 for p in git('ls-files','--others','--exclude-standard').splitlines():
  if p in GOV:continue
  data=(ROOT/p).read_bytes();stats[p]=(data.count(b'\n')+(bool(data)and not data.endswith(b'\n')),0)
 if sorted(stats)!=v['functional_paths']:raise GateError('worktree allowlist')
 a=sum(x for x,_ in stats.values());d=sum(x for _,x in stats.values())
 if(len(stats),a,d,a-d)!=(36,1237,63,1174):raise GateError('worktree budget')
 return True
def require_single_parent(commit,parent,label):
 if parents(commit)!=[parent]:raise GateError(f'{label} parent')
def validate_review(raw,role,a,a_tree):
 v=load_bytes(raw);exact(v,{'schema','role','reviewed_commit','reviewed_tree','verdict','findings'},'review')
 if v!={'schema':'ese.v92.o01-review/v1','role':role,'reviewed_commit':a,'reviewed_tree':a_tree,'verdict':'APPROVE','findings':[]}:raise GateError('review content')
def verify_h(h,a,g):
 require_single_parent(h,a,'H')
 if changed(a,h)!=H_PATHS:raise GateError('H delta')
 a_tree=git('rev-parse',f'{a}^{{tree}}');amend=sha(blob(g,DOC));paths_sha=sha(canonical(functional_paths()))
 act=load_bytes(blob(h,H_PATHS[0]));exact(act,{'schema','g_commit','a_commit','a_tree','amendment_sha256','functional_paths_sha256','artifact_sha256'},'activation')
 artifact_hashes={p:sha(blob(h,p)) for p in H_PATHS[1:]}
 if act!={'schema':'ese.v92.o01-activation/v1','g_commit':g,'a_commit':a,'a_tree':a_tree,'amendment_sha256':amend,'functional_paths_sha256':paths_sha,'artifact_sha256':artifact_hashes}:raise GateError('activation content')
 validate_review(blob(h,H_PATHS[2]),'Sol',a,a_tree);validate_review(blob(h,H_PATHS[3]),'Terra',a,a_tree)
 off=load_bytes(blob(h,H_PATHS[1]));exact(off,{'schema','source_commit','source_tree','amendment_sha256','gates'},'offline')
 if off['schema']!='ese.v92.o01-offline-summary/v1'or off['source_commit']!=a or off['source_tree']!=a_tree or off['amendment_sha256']!=amend or not isinstance(off['gates'],list)or len(off['gates'])!=8:raise GateError('offline content')
 for item,(name,command,marker) in zip(off['gates'],OFFLINE):
  exact(item,{'name','command','exit_code','marker','body','body_sha256'},'offline gate')
  if item['name']!=name or item['command']!=command or item['exit_code']!=0 or item['marker']!=marker or item['body']!=[marker] or item['body_sha256']!=sha(canonical(item['body'])):raise GateError('offline gate')
def verify_s(s,h,a):
 require_single_parent(s,h,'S')
 if changed(h,s)!=S_PATHS:raise GateError('S delta')
 raw=blob(s,S_PATHS[0]);rv=load_bytes(raw);exact(rv,{'schema','verdict','release_gate','source_commit','baseline_restored'},'smoke raw')
 if rv['release_gate']is not False or rv['verdict']!='PASS'or rv['source_commit']!=a or rv['baseline_restored']is not True:raise GateError('smoke claim')
 summary=load_bytes(blob(s,S_PATHS[1]));
 if summary!={'schema':'ese.v92.o01-nonrelease-summary/v1','h_commit':h,'source_commit':a,'raw_sha256':sha(raw),'release_gate':False,'verdict':'PASS'}:raise GateError('smoke summary')
def r_paths():return sorted([f'artifacts/v92-o01-formal/checkpoint-{i:02}.json' for i in range(1,96)]+['artifacts/v92-o01-formal/controller-result.json','artifacts/v92-o01-formal/formal-run-result.json','artifacts/v92-o01-formal/formal-validation.json'])
def run_product_validator(materialized:Path):
 validator=materialized/'validator.js';scenario=materialized/'scenario.json';script="const fs=require('fs'),p=require('path'),d=process.argv[1],v=require(p.join(d,'validator.js')),c=JSON.parse(fs.readFileSync(p.join(d,'scenario.json'))),r=JSON.parse(fs.readFileSync(p.join(d,'controller-result.json'))),x=Array.from({length:95},(_,i)=>JSON.parse(fs.readFileSync(p.join(d,'checkpoint-'+String(i+1).padStart(2,'0')+'.json'))));v._validateFormalEvidenceTest({config:c,checkpoints:x,result:r});process.stdout.write('PASS');"
 out=subprocess.run(['node','-e',script,str(materialized)],cwd=ROOT,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120).stdout
 if out!=b'PASS':raise GateError('product validator output')
def verify_r(r,parent,a,h,s):
 require_single_parent(r,parent,'R')
 if changed(parent,r)!=r_paths():raise GateError('R delta')
 a_tree=git('rev-parse',f'{a}^{{tree}}');run_path='artifacts/v92-o01-formal/formal-run-result.json';controller_path='artifacts/v92-o01-formal/controller-result.json';validation_path='artifacts/v92-o01-formal/formal-validation.json'
 run_raw=blob(r,run_path);controller_raw=blob(r,controller_path);run=load_bytes(run_raw);result=load_bytes(controller_raw);validation=load_bytes(blob(r,validation_path))
 exact(run,{'schema','verdict','release_gate','source_commit','source_tree','governance_h_commit','governance_s_commit','executable_sha256','build_info_sha256','node_sha256','duration_ms','product_records','checkpoints','fault_slots','baseline_restored','independent_validation'},'formal run')
 if run.get('schema')!='ese.v92.o01-formal-run/v1'or run.get('verdict')!='PASS'or run.get('release_gate')is not True or run.get('duration_ms')!=28800000 or run.get('source_commit')!=a or run.get('source_tree')!=a_tree or run.get('governance_h_commit')!=h or run.get('governance_s_commit')!=s or run.get('baseline_restored')is not True or run.get('independent_validation')is not True:raise GateError('formal run')
 if run['product_records']!=482 or run['checkpoints']!=95 or run['fault_slots']!=960 or any(not isinstance(run[k],str)or not re.fullmatch(r'[a-f0-9]{64}',run[k])for k in ('executable_sha256','build_info_sha256','node_sha256')):raise GateError('formal run metrics')
 if result.get('source_commit')!=a or result.get('source_tree')!=a_tree or result.get('verdict')!='PASS'or result.get('checkpoint_count')!=95:raise GateError('controller result')
 raw={controller_path:controller_raw,run_path:run_raw};checkpoints=[]
 for i in range(1,96):
  path=f'artifacts/v92-o01-formal/checkpoint-{i:02}.json';data=blob(r,path);raw[path]=data;checkpoints.append(data)
 expected_hashes={path:sha(data) for path,data in sorted(raw.items())};exact(validation,{'schema','verdict','source_commit','source_tree','governance_h_commit','governance_s_commit','validator_sha256','scenario_sha256','artifacts_sha256','chain_tip_sha256','checkpoints','fault_slots','ticks','samples'},'formal validation')
 validator_blob=blob(a,'tools/lab/nat_gateway/v92_o01_validate_formal.js');scenario_blob=blob(a,'tools/lab/nat_gateway/v92_o01_scenario.json')
 if validation!={'schema':'ese.v92.o01-formal-validation/v2','verdict':'PASS','source_commit':a,'source_tree':a_tree,'governance_h_commit':h,'governance_s_commit':s,'validator_sha256':sha(validator_blob),'scenario_sha256':sha(scenario_blob),'artifacts_sha256':expected_hashes,'chain_tip_sha256':result.get('chain_tip_sha256'),'checkpoints':95,'fault_slots':960,'ticks':2880,'samples':480}:raise GateError('formal validation')
 config=load_bytes(scenario_blob)
 if result.get('bound_files') is None or [x.get('path') for x in result['bound_files']]!=config.get('bound_files'):raise GateError('A bound paths')
 for entry in result['bound_files']:
  if entry.get('sha256')!=sha(blob(a,entry['path'])):raise GateError('A bound hash')
 with tempfile.TemporaryDirectory(prefix='o01-governance-')as td:
  root=Path(td);(root/'validator.js').write_bytes(validator_blob);(root/'scenario.json').write_bytes(scenario_blob);(root/'controller-result.json').write_bytes(controller_raw)
  for i,data in enumerate(checkpoints,1):(root/f'checkpoint-{i:02}.json').write_bytes(data)
  run_product_validator(root)
def autodetect(v):
 head=git('rev-parse','HEAD')
 if head==BASE:
  worktree_stats(v);return'DRAFT_WORKTREE'
 ps=parents(head)
 if ps==[BASE] and changed(BASE,head)==sorted(GOV) and load_bytes(blob(head,DOC))==v:return'G'
 # Walk the strict first-parent chain and recognize G/A/H/S/R without trusting subjects.
 chain=[];cur=head
 while cur!=BASE and len(chain)<6:
  chain.append(cur);p=parents(cur)
  if len(p)!=1:raise GateError('merge topology')
  cur=p[0]
 if cur!=BASE:raise GateError('base ancestry')
 chain.reverse();g=chain[0]
 if changed(BASE,g)!=sorted(GOV):raise GateError('G delta')
 if len(chain)==1:return'G'
 a=chain[1];require_single_parent(a,g,'A')
 if changed(g,a)!=functional_paths():raise GateError('A delta')
 commit_budget(g,a)
 if len(chain)==2:return'A'
 h=chain[2];verify_h(h,a,g)
 if len(chain)==3:return'H'
 fourth=chain[3]
 if changed(h,fourth)==S_PATHS:
  verify_s(fourth,h,a)
  if len(chain)==4:return'S'
  if len(chain)!=5:raise GateError('intermediate after S')
  verify_r(chain[4],fourth,a,h,fourth);return'R'
 if len(chain)!=4:raise GateError('intermediate before R')
 verify_r(fourth,h,a,h,None);return'R'
def main():
 p=argparse.ArgumentParser();p.add_argument('--check-worktree',action='store_true');p.add_argument('--verify',action='store_true');args=p.parse_args()
 try:
  v=load();validate(v)
  state=autodetect(v) if args.verify else ('DRAFT_WORKTREE' if args.check_worktree and worktree_stats(v) else'DOCUMENT')
 except(Exception) as exc:
  if not isinstance(exc,(GateError,ValueError,OSError,subprocess.SubprocessError)):raise
  print(f'V92_O01_GOVERNANCE_FAIL {exc}',file=sys.stderr);return 1
 print(f'V92_O01_GOVERNANCE_PASS state={state} paths=36 add=1237 delete=63 net=1174');return 0
if __name__=='__main__':raise SystemExit(main())
