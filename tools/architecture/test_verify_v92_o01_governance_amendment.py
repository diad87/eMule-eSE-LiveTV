import copy,importlib.util,json,pathlib,subprocess,unittest
from unittest.mock import patch
P=pathlib.Path(__file__).with_name('verify_v92_o01_governance_amendment.py');S=importlib.util.spec_from_file_location('o01gov',P);M=importlib.util.module_from_spec(S);S.loader.exec_module(M)
class TestO01Governance(unittest.TestCase):
 def test_canonical_and_current_phase(self):
  self.assertTrue(M.validate(M.load()));self.assertIn(M.autodetect(M.load()),{'DRAFT_WORKTREE','G','A','H','S','R'})
 def test_normative_text_lists_and_base_are_exact(self):
  mutations=[lambda v:v.__setitem__('base_commit','0'*40),lambda v:v['functional_paths'].reverse(),lambda v:v['budget'].__setitem__('add_exact',1230),lambda v:v['required_reviews'].__setitem__(0,'Terra maybe'),lambda v:v['offline_gates'].pop(),lambda v:v['stop_conditions'].__setitem__(0,'later'),lambda v:v['phase_contract']['R'].__setitem__('parent','anything')]
  for mutation in mutations:
   value=copy.deepcopy(M.load());mutation(value)
   with self.assertRaises(M.GateError):M.validate(value)
 def test_staged_delta_cannot_bypass_head_diff(self):
  calls=[]
  def fake(*args):
   calls.append(args)
   if args[:3]==('diff','HEAD','--numstat'):return '1\t0\ttools/lab/staged-only.js'
   if args[:3]==('ls-files','--others','--exclude-standard'):return''
   return''
  with patch.object(M,'git',side_effect=fake):
   with self.assertRaisesRegex(M.GateError,'worktree allowlist'):M.worktree_stats(M.load())
  self.assertIn(('diff','HEAD','--numstat','--'),calls)
 def test_wrong_parent_and_merge_are_rejected(self):
  with patch.object(M,'parents',return_value=['wrong']):
   with self.assertRaisesRegex(M.GateError,'A parent'):M.require_single_parent('a','g','A')
  with patch.object(M,'parents',return_value=['one','two']):
   with self.assertRaisesRegex(M.GateError,'R parent'):M.require_single_parent('r','s','R')
 def test_a_budget_is_exact(self):
  with patch.object(M,'git',return_value='1220\t63\ttools/lab/one.js'):
   with self.assertRaisesRegex(M.GateError,'A budget'):M.commit_budget('g','a')
 def test_missing_or_nonapprove_review_is_rejected(self):
  for value in ({},{'schema':'ese.v92.o01-review/v1','role':'Sol','reviewed_commit':'a','reviewed_tree':'t','verdict':'REJECT','findings':[]}):
   with self.assertRaises(M.GateError):M.validate_review(json.dumps(value).encode(),'Sol','a','t')
 def test_h_activation_requires_exact_sibling_hashes(self):
  review=lambda role:json.dumps({'schema':'ese.v92.o01-review/v1','role':role,'reviewed_commit':'a','reviewed_tree':'tree','verdict':'APPROVE','findings':[]}).encode()
  amendment=b'amendment';amendment_sha=M.sha(amendment);offline=json.dumps({'schema':'ese.v92.o01-offline-summary/v1','source_commit':'a','source_tree':'tree','amendment_sha256':amendment_sha,'gates':[{'name':n,'verdict':'PASS','output_sha256':'1'*64}for n in M.GATES]}).encode()
  blobs={M.DOC:amendment,M.H_PATHS[1]:offline,M.H_PATHS[2]:review('Sol'),M.H_PATHS[3]:review('Terra')};activation={'schema':'ese.v92.o01-activation/v1','g_commit':'g','a_commit':'a','a_tree':'tree','amendment_sha256':amendment_sha,'functional_paths_sha256':M.sha(M.canonical(M.functional_paths())),'artifact_sha256':{p:'0'*64 for p in M.H_PATHS[1:]}};blobs[M.H_PATHS[0]]=json.dumps(activation).encode()
  with patch.object(M,'parents',return_value=['a']),patch.object(M,'changed',return_value=M.H_PATHS),patch.object(M,'git',return_value='tree'),patch.object(M,'blob',side_effect=lambda c,p:blobs[p]):
   with self.assertRaisesRegex(M.GateError,'activation content'):M.verify_h('h','a','g')
 def test_h_rejects_orphan_offline_body_hash(self):
  amendment=b'amendment';amendment_sha=M.sha(amendment);review=lambda role:json.dumps({'schema':'ese.v92.o01-review/v1','role':role,'reviewed_commit':'a','reviewed_tree':'tree','verdict':'APPROVE','findings':[]}).encode();gates=[{'name':n,'command':c,'exit_code':0,'marker':m,'body':[m],'body_sha256':'0'*64}for n,c,m in M.OFFLINE];offline=json.dumps({'schema':'ese.v92.o01-offline-summary/v1','source_commit':'a','source_tree':'tree','amendment_sha256':amendment_sha,'gates':gates}).encode();blobs={M.DOC:amendment,M.H_PATHS[1]:offline,M.H_PATHS[2]:review('Sol'),M.H_PATHS[3]:review('Terra')};activation={'schema':'ese.v92.o01-activation/v1','g_commit':'g','a_commit':'a','a_tree':'tree','amendment_sha256':amendment_sha,'functional_paths_sha256':M.sha(M.canonical(M.functional_paths())),'artifact_sha256':{p:M.sha(blobs[p])for p in M.H_PATHS[1:]}};blobs[M.H_PATHS[0]]=json.dumps(activation).encode()
  with patch.object(M,'parents',return_value=['a']),patch.object(M,'changed',return_value=M.H_PATHS),patch.object(M,'git',return_value='tree'),patch.object(M,'blob',side_effect=lambda c,p:blobs[p]):
   with self.assertRaisesRegex(M.GateError,'offline gate'):M.verify_h('h','a','g')
 def test_smoke_hash_claim_and_topology_are_closed(self):
  raw={'schema':'ese.v92.o01-vm-t8-product-smoke/v1','verdict':'PASS','release_gate':False,'source_commit':'a','baseline_restored':True}
  summary={'schema':'ese.v92.o01-nonrelease-summary/v1','h_commit':'h','source_commit':'a','raw_sha256':'0'*64,'release_gate':False,'verdict':'PASS'}
  def blobs(commit,path):return json.dumps(raw if path==M.S_PATHS[0] else summary).encode()
  with patch.object(M,'parents',return_value=['h']),patch.object(M,'changed',return_value=M.S_PATHS),patch.object(M,'blob',side_effect=blobs):
   with self.assertRaisesRegex(M.GateError,'smoke summary'):M.verify_s('s','h','a')
  raw['release_gate']=True
  with patch.object(M,'parents',return_value=['h']),patch.object(M,'changed',return_value=M.S_PATHS),patch.object(M,'blob',side_effect=blobs):
   with self.assertRaisesRegex(M.GateError,'smoke claim'):M.verify_s('s','h','a')
 def test_r_missing_artifact_and_wrong_parent_fail(self):
  with patch.object(M,'parents',return_value=['not-h']),patch.object(M,'changed',return_value=M.r_paths()):
   with self.assertRaisesRegex(M.GateError,'R parent'):M.verify_r('r','h','a','h',None)
  with patch.object(M,'parents',return_value=['h']),patch.object(M,'changed',return_value=M.r_paths()[:-1]):
   with self.assertRaisesRegex(M.GateError,'R delta'):M.verify_r('r','h','a','h',None)
 def test_r_rejects_governance_commit_as_source_even_with_superficial_pass(self):
  run={'schema':'ese.v92.o01-formal-run/v1','verdict':'PASS','release_gate':True,'duration_ms':28800000,'source_commit':'h','source_tree':'tree','governance_h_commit':'h','governance_s_commit':None,'executable_sha256':'1'*64,'build_info_sha256':'2'*64,'node_sha256':'3'*64,'product_records':482,'checkpoints':95,'fault_slots':960,'baseline_restored':True,'independent_validation':True};values={'artifacts/v92-o01-formal/formal-run-result.json':run,'artifacts/v92-o01-formal/controller-result.json':{},'artifacts/v92-o01-formal/formal-validation.json':{}}
  with patch.object(M,'parents',return_value=['h']),patch.object(M,'changed',return_value=M.r_paths()),patch.object(M,'git',return_value='tree'),patch.object(M,'blob',side_effect=lambda c,p:json.dumps(values.get(p,{})).encode()):
   with self.assertRaisesRegex(M.GateError,'formal run'):M.verify_r('r','h','a','h',None)
 def test_r_rejects_edited_run_even_when_superficial_fields_are_updated(self):
  run={'schema':'ese.v92.o01-formal-run/v1','verdict':'PASS','release_gate':True,'duration_ms':28800000,'source_commit':'a','source_tree':'tree','governance_h_commit':'h','governance_s_commit':None,'executable_sha256':'1'*64,'build_info_sha256':'2'*64,'node_sha256':'3'*64,'product_records':482,'checkpoints':95,'fault_slots':960,'baseline_restored':True,'independent_validation':True,'edited_controller_sha256':'4'*64};values={'artifacts/v92-o01-formal/formal-run-result.json':run,'artifacts/v92-o01-formal/controller-result.json':{},'artifacts/v92-o01-formal/formal-validation.json':{}}
  with patch.object(M,'parents',return_value=['h']),patch.object(M,'changed',return_value=M.r_paths()),patch.object(M,'git',return_value='tree'),patch.object(M,'blob',side_effect=lambda c,p:json.dumps(values.get(p,{})).encode()):
   with self.assertRaisesRegex(M.GateError,'formal run schema'):M.verify_r('r','h','a','h',None)
 def test_product_validator_negative_campaign_covers_forgery_and_chain(self):
  result=subprocess.run(['node','--test',str(M.ROOT/'tools/lab/nat_gateway/test/v92_o01_validate_formal.test.js')],cwd=M.ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True,text=True)
  self.assertIn('rejects missing, reordered, edited and false cleanup evidence',result.stdout)
 def test_release_claim_text_is_closed(self):self.assertEqual(M.load()['physical_policy']['claim_rule'],'No physical or release PASS may be claimed from mocks, a non-elevated attempt, or the short smoke.')
if __name__=='__main__':unittest.main()
