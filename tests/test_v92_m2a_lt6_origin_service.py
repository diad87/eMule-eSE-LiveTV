import pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; SRC=ROOT/"srchybrid"
SH,SC=SRC/"LiveTunnelOriginService.h",SRC/"LiveTunnelOriginService.cpp"
WH,WC=SRC/"LiveTunnelOriginWorker.h",SRC/"LiveTunnelOriginWorker.cpp"
FACADE=(SRC/"LiveTunnel.h").read_text()+(SRC/"LiveTunnel.cpp").read_text()
KH=(SRC/"LiveTunnelKadBridge.h").read_text(); KC=(SRC/"LiveTunnelKadBridge.cpp").read_text()
PROJECT=(SRC/"emule.vcxproj").read_text()
FIELDS="""m_k6OriginSourceLookups m_k6DownloadActivations m_k6OriginSourceLeaseRoutes
m_k6OriginPublishLeaseRoutes m_k6OriginAdvertisements m_k6OriginSourceEpoch
m_k6OriginTargetRoutes m_k6OriginLiveRoutes""".split()
class LT6OriginService(unittest.TestCase):
 def setUp(self):
  for p in (SH,SC,WH,WC): self.assertTrue(p.is_file(),f"missing {p.name}")
  self.sh,self.sc,self.wh,self.wc=(p.read_text() for p in (SH,SC,WH,WC))
 def test_eight_fields_have_one_physical_owner(self):
  for f in FIELDS:
   self.assertEqual(len(re.findall(rf"\b{re.escape(f)}\b",self.sh)),1)
   self.assertNotIn(f,FACADE); self.assertNotIn(f,KH)
 def test_service_and_worker_are_physically_bound(self):
  for marker,code in (("M2A_BIND_LT6_8E07B736A1",self.sc+KC),("M2A_BIND_LT6_6F855B99C0",self.wc+self.sc),
                      ("m_m2a_binding_8e07b736a1",KH+KC),("m_m2a_binding_6f855b99c0",self.sh+self.sc)):
   self.assertIn(marker,code)
  for name in ("LiveTunnelOriginService.cpp","LiveTunnelOriginWorker.cpp"): self.assertIn(name,PROJECT)
 def test_worker_is_cancelable_and_cannot_reach_the_coordinator(self):
  worker=self.wh+self.wc
  for forbidden in ("LiveTunnel.h","CLiveTunnel"): self.assertNotIn(forbidden,worker)
  for marker in ("Cancel","generation","stale","Join"): self.assertIn(marker,worker)
 def test_state_transitions_are_closed_and_snapshot_external_actions(self):
  code=self.sh+self.sc
  for marker in ("ReserveAdvertise","FinishAdvertise","AddSourceRoute","TakeSourceRoute","AddPublishRoute",
                 "TakePublishRoute","AddSourceLookup","AddDownloadActivation","Sweep"): self.assertIn(marker,code)
  self.assertNotIn("CUpDownClient*",self.sh); self.assertIn("LiveTunnelOriginAction",code)
 def test_sweep_is_a_small_facade_and_external_effects_stay_outside_owner(self):
  source=(SRC/"Kad6GatewaySocket.cpp").read_text()
  match=re.search(r"void\s+CLiveTunnel::SweepK6Gateway\s*\([^)]*\)\s*\{([\s\S]*?)\n\}",source)
  self.assertIsNotNone(match); self.assertLessEqual(len(match.group(0).splitlines()),150); self.assertIn("LT6",match.group(0))
  for forbidden in ("Disconnected(","EnqueueSendMsg(","CompleteExitOperation("): self.assertNotIn(forbidden,self.sc)
 def test_productive_characterization_covers_required_failures(self):
  code=self.sc+self.wc; self.assertIn("RunLiveTunnelOriginServiceCharacterizationSelfTest",code)
  for marker in ("WorkerCanceled","StaleResultIgnored","TimerCoalesced","LeaseRouteRemoved","AdvertiseRollback"): self.assertIn(marker,code)
 def test_budgets(self):
  self.assertLessEqual(len(self.sh.splitlines())+len(self.sc.splitlines()),1100)
  self.assertLessEqual(len(self.wh.splitlines())+len(self.wc.splitlines()),700)
class LT6TypedEvidence(unittest.TestCase):
 def test_m2a_a0f3088c95ceaf20(self): self.assertIn("M2A_BIND_LT6_8E07B736A1",SC.read_text())
 def test_m2a_6cbfc1985b62933a(self): self.assertIn("M2A_BIND_LT6_6F855B99C0",WC.read_text())
 def test_m2a_b83dadd1eda5dc6b(self): self.assertIn("WorkerCanceled",SC.read_text()+WC.read_text())
 def test_m2a_fd334c273290db83(self): self.assertTrue(all(f in SH.read_text() for f in FIELDS))
 def test_m2a_6b33ffd476ff6805(self):
  self.assertIn("CLiveTunnel::SweepK6Gateway",(SRC/"Kad6GatewaySocket.cpp").read_text())
 def test_m2a_b714f8cd4b994f4c(self): self.assertIn("class LiveTunnelOriginService",SH.read_text())
 def test_m2a_2c5df72f3c564e3a(self): self.assertIn("class LiveTunnelOriginWorker",WH.read_text())
if __name__=="__main__": unittest.main()
