// this file is part of eMule eSE - neutral LT7 bulk/proxy state port
#pragma once
#include "LiveBulk.h"
#include "LiveCellQueue.h"
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>
namespace eSELive {
struct BulkReasmEntry {
  std::uint8_t streamKey[16] = {0};
  std::uint32_t seq = 0, msg_len = 0;
  std::uint8_t n_blocks = 0, r = 0;
  DWORD first_seen_tick = 0, lastNackTick = 0;
  bool done = false, haveLayout = false;
  Bulk::BulkLayout layout; std::vector<int> blockRecv;
  std::vector<Bulk::BulkSymbol> symbols;
};
struct ProxyFrag {
  std::uint32_t totalLen = 0; std::uint16_t fragCount = 0, haveCount = 0;
  DWORD firstTick = 0; std::vector<std::uint8_t> buf; std::vector<bool> got;
};
struct BulkSub {
  std::uint32_t circ_id = 0, session_id = 0; std::uint16_t shape_bucket_kib = 0;
  std::uint8_t r_pref = 0; bool shaped = false; DWORD lastSeen = 0;
};
struct ProxyRecentRec {
  std::uint8_t streamKey[16] = {0}; std::uint32_t seq = 0;
  std::vector<std::uint8_t> record; DWORD tick = 0;
};
struct ProxyStreamCtl {
  int r = Bulk::BULK_DEFAULT_R; std::uint32_t nackCount = 0; DWORD windowStart = 0;
};
struct ExitLiveSub { DWORD lastSeen = 0; };
struct ExitStreamProxy {
  std::uint8_t streamKey[16] = {0}; std::uint32_t bIP = 0; std::uint16_t bPort = 0;
  std::map<std::uint32_t, ExitLiveSub> circuits;
};

struct LiveTunnelBulkStatePort {
  std::map<std::string, BulkReasmEntry> *BulkReassemblyState = nullptr; std::map<std::uint32_t, Bulk::BulkReplayWindow> *BulkReplayState = nullptr;
  std::mutex *ProxyIngestMutex = nullptr; std::set<std::string> *ProxyKeySet = nullptr;
  std::map<std::string, ProxyFrag> *ProxyFragmentState = nullptr; std::deque<std::vector<std::uint8_t>> *ProxyReadyQueue = nullptr;
  std::map<std::string, std::vector<BulkSub>> *BulkSubscriptions = nullptr; std::deque<ProxyRecentRec> *ProxyRecentRecords = nullptr;
  std::map<std::string, ProxyStreamCtl> *ProxyControlState = nullptr; std::map<std::uint64_t, ReassemblyEntry> *RelayReassemblyState = nullptr;
  std::map<std::string, ExitStreamProxy> *ExitLiveSubscriptions = nullptr;
};
} // namespace eSELive
