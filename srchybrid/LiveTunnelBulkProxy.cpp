// this file is part of eMule eSE - LT7 bulk/proxy state owner
#include "stdafx.h"
#include "LiveTunnelBulkProxy.h"

namespace eSELive {

M2AModuleHandle M2A_BIND_LT7_CAC245F7E7(const M2AParentPort &);
LiveTunnelBulkTransportAdapter *ResolveLiveTunnelBulkTransportAdapter(M2AModuleHandle &) noexcept;
const LiveTunnelBulkTransportAdapter *ResolveLiveTunnelBulkTransportAdapter(const M2AModuleHandle &) noexcept;
bool RunLiveTunnelBulkTransportAdapterCharacterizationSelfTest(LiveTunnelBulkTransportAdapter *);
bool AcceptLiveTunnelBulkTransportReplay(LiveTunnelBulkTransportAdapter *, std::uint32_t, std::uint64_t) noexcept;

bool M2A_LT7_BulkReplayBridge(void *context, std::uint32_t circuitId, std::uint64_t nonceSequence) noexcept {
  LiveTunnelBulkProxy *owner = static_cast<LiveTunnelBulkProxy *>(context);
  return owner && circuitId != 0 && owner->m_bulkReplay[circuitId].Check(nonceSequence);
}

LiveTunnelBulkProxy::LiveTunnelBulkProxy(const M2AParentPort &) noexcept
    : m_m2a_binding_cac245f7e7(M2AAssignmentPolicy::RetainExisting) {
  m_m2a_binding_cac245f7e7 =
      M2A_BIND_LT7_CAC245F7E7(M2AParentPort{this});
}

LiveTunnelBulkTransportAdapter *LiveTunnelBulkProxy::Adapter() noexcept { return ResolveLiveTunnelBulkTransportAdapter(m_m2a_binding_cac245f7e7); }

const LiveTunnelBulkTransportAdapter *LiveTunnelBulkProxy::Adapter() const noexcept { return ResolveLiveTunnelBulkTransportAdapter(m_m2a_binding_cac245f7e7); }
bool LiveTunnelBulkProxy::AcceptReplay(std::uint32_t circuitId, std::uint64_t nonceSequence) noexcept { return AcceptLiveTunnelBulkTransportReplay(Adapter(), circuitId, nonceSequence); }

LiveTunnelBulkStatePort M2A_LT7_StateBridge(M2AModuleHandle &handle) noexcept {
  LiveTunnelBulkProxy *owner = ResolveLiveTunnelBulkProxy(handle);
  if (!owner) return {};
  return {&owner->m_bulkReasm, &owner->m_bulkReplay, &owner->m_proxyIngestLock, &owner->m_proxyKeys,
          &owner->m_proxyFragReasm, &owner->m_proxyReady, &owner->m_bulkSubs, &owner->m_proxyRecent,
          &owner->m_proxyCtl, &owner->m_reassembly, &owner->m_exitLiveSubs};
}
bool M2A_LT7_AcceptReplayBridge(M2AModuleHandle &handle, std::uint32_t circuitId, std::uint64_t nonceSequence) noexcept {
  LiveTunnelBulkProxy *owner = ResolveLiveTunnelBulkProxy(handle);
  return owner && owner->AcceptReplay(circuitId, nonceSequence);
}
bool M2A_LT7_AcceptFragmentBridge(M2AModuleHandle &handle,const std::string& key,std::uint16_t index,std::uint16_t count,std::uint32_t total,const std::uint8_t* data,std::uint32_t length,std::uint32_t offset,DWORD now) noexcept { LiveTunnelBulkProxy *owner=ResolveLiveTunnelBulkProxy(handle); return owner && owner->AcceptFragment(key,index,count,total,data,length,offset,now); }

bool LiveTunnelBulkProxy::AcceptFragment(const std::string& key,std::uint16_t index,std::uint16_t count,std::uint32_t total,const std::uint8_t* data,std::uint32_t length,std::uint32_t offset,DWORD now) noexcept {
  if (!count || index>=count || !total || !data || offset>total || length>total-offset) return false; std::lock_guard<std::mutex> leaf(m_proxyIngestLock);
  auto item = m_proxyFragReasm.find(key);
  if (item == m_proxyFragReasm.end()) {
    if (m_proxyFragReasm.size() >= 8 /* ESE_FRAG_MAX_CONCURRENT */) {
      auto oldest = m_proxyFragReasm.begin();
      for (auto it = m_proxyFragReasm.begin(); it != m_proxyFragReasm.end(); ++it)
        if (static_cast<LONG>(it->second.firstTick - oldest->second.firstTick) < 0) oldest = it;
      m_proxyFragReasm.erase(oldest);
    }
    ProxyFrag fresh; fresh.totalLen=total; fresh.fragCount=count; fresh.firstTick=now; fresh.buf.resize(total); fresh.got.assign(count,false);
    item=m_proxyFragReasm.emplace(key,std::move(fresh)).first;
  } else if (item->second.totalLen != total || item->second.fragCount != count) {
    ProxyFrag& fragment=item->second; fragment.totalLen=total; fragment.fragCount=count; fragment.haveCount=0; fragment.firstTick=now;
    fragment.buf.assign(total,0); fragment.got.assign(count,false);
  }
  ProxyFrag& fragment=item->second;
  if (fragment.got[index]) return false;
  memcpy(fragment.buf.data()+offset,data,length); fragment.got[index]=true;
  if (++fragment.haveCount == fragment.fragCount) { m_proxyReady.push_back(std::move(fragment.buf)); m_proxyFragReasm.erase(item); while (m_proxyReady.size()>64) m_proxyReady.pop_front(); }
  return true;
}

void LiveTunnelBulkProxy::Clear() noexcept {
  m_bulkReasm.clear();
  m_bulkReplay.clear();
  {
    std::lock_guard<std::mutex> leaf(m_proxyIngestLock);
    m_proxyKeys.clear();
    m_proxyFragReasm.clear();
    m_proxyReady.clear();
  }
  m_bulkSubs.clear();
  m_proxyRecent.clear();
  m_proxyCtl.clear();
  m_reassembly.clear();
  m_exitLiveSubs.clear();
}

std::size_t LiveTunnelBulkProxy::RemoveCircuitReassembly(std::uint32_t circuitId) noexcept {
  std::size_t removed = 0;
  for (auto entry = m_reassembly.begin(); entry != m_reassembly.end();) {
    if (static_cast<std::uint32_t>(entry->first >> 32) == circuitId) {
      entry = m_reassembly.erase(entry);
      ++removed;
    } else {
      ++entry;
    }
  }
  return removed;
}

std::size_t LiveTunnelBulkProxy::SweepRelayReassembly(DWORD now, DWORD ttl) noexcept {
  std::size_t removed = 0;
  for (auto entry = m_reassembly.begin(); entry != m_reassembly.end();) {
    if (static_cast<std::uint32_t>(now - entry->second.first_seen_tick) > ttl) {
      entry = m_reassembly.erase(entry);
      ++removed;
    } else {
      ++entry;
    }
  }
  return removed;
}

M2AModuleHandle M2A_BIND_LT7_9EA638E856(const M2AParentPort &parent) { return MakeM2AModuleHandle(new LiveTunnelBulkProxy(parent)); }

LiveTunnelBulkProxy *ResolveLiveTunnelBulkProxy(M2AModuleHandle &handle) noexcept { return static_cast<LiveTunnelBulkProxy *>(handle.Get()); }

const LiveTunnelBulkProxy *ResolveLiveTunnelBulkProxy(const M2AModuleHandle &handle) noexcept { return static_cast<const LiveTunnelBulkProxy *>(handle.Get()); }

bool RunLiveTunnelBulkProxyCharacterizationSelfTest() {
  int parent = 0;
  LiveTunnelBulkProxy proxy(M2AParentPort{&parent});
  if (!proxy.Adapter() || !proxy.m_bulkReasm.empty() || !proxy.m_bulkReplay.empty() || !proxy.m_proxyKeys.empty() || !proxy.m_proxyFragReasm.empty() || !proxy.m_proxyReady.empty() || !proxy.m_bulkSubs.empty() || !proxy.m_proxyRecent.empty() || !proxy.m_proxyCtl.empty() || !proxy.m_reassembly.empty() || !proxy.m_exitLiveSubs.empty()) return false;
  const std::uint8_t first[]={1,2},second[]={3,4};
  if (!proxy.AcceptFragment("record",1,2,4,second,2,2,1) || proxy.AcceptFragment("record",1,2,4,second,2,2,2) || !proxy.m_proxyReady.empty()) return false;
  if (!proxy.AcceptFragment("record",0,2,4,first,2,0,3) || proxy.m_proxyReady.size()!=1 || proxy.m_proxyReady.front()!=std::vector<std::uint8_t>({1,2,3,4})) return false;
  proxy.m_reassembly[(std::uint64_t(7)<<32)|1].first_seen_tick=1; proxy.m_reassembly[(std::uint64_t(8)<<32)|1].first_seen_tick=1;
  if (proxy.RemoveCircuitReassembly(7)!=1 || proxy.SweepRelayReassembly(10, 5)!=1) return false;
  proxy.Clear();
  return proxy.m_proxyReady.empty() && proxy.m_proxyFragReasm.empty() && proxy.m_reassembly.empty() && RunLiveTunnelBulkTransportAdapterCharacterizationSelfTest(proxy.Adapter());
}

} // namespace eSELive
