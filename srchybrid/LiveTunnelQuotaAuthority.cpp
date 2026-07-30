#include "LiveTunnelQuotaAuthority.h"
#include "Kad6QuotaCrypto.h"
#include "kad6/kad6_economy.h"
#include "kad6/kad6_frontdoor.h"
#include "kad6/kad6_hardening.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <map>
#include <string>
#include <vector>

namespace eSELive {

LiveTunnelQuotaAuthority::LiveTunnelQuotaAuthority(
    const M2AParentPort &) noexcept {}

LiveTunnelQuotaAuthority::~LiveTunnelQuotaAuthority() noexcept = default;

M2AModuleHandle M2A_BIND_LT2_8892179A6E(const M2AParentPort &parent) {
  return MakeM2AModuleHandle(new LiveTunnelQuotaAuthority(parent));
}

struct LiveTunnelQuotaBridge {
  template <typename T>
  static LiveTunnelQuotaAuthority::Store Own(T *value) noexcept {
    return LiveTunnelQuotaAuthority::Store(
        value, [](void *raw) { delete static_cast<T *>(raw); });
  }
  using Inputs = std::array<kad6::K6SaturationInputs,
                            static_cast<size_t>(kad6::K6Service::Count)>;
  struct Grant {
    kad6::K6QuotaService service = kad6::K6QuotaService::Control;
    kad6::Hash32 context{};
    kad6::Hash32 issuer{};
    std::uint64_t allocation_id = 0;
    std::uint64_t expires_at = 0;
  };
  using Grants = std::map<std::string, Grant>;
  struct PendingGrant {
    bool ready = false;
    std::string key;
    Grant grant;
  };
  // Called exactly once by LiveTunnelScheduler while its constructor still
  // has exclusive ownership of the unpublished module handle.
  static void InitializeBeforePublication(LiveTunnelQuotaAuthority &owner) {
    if (!owner.m_k6Hardening)
      owner.m_k6Hardening = Own(new kad6::K6HardeningController());
    if (!owner.m_k6EconomyTelemetry)
      owner.m_k6EconomyTelemetry = Own(new kad6::K6EconomyTelemetry());
    if (!owner.m_k6EconomyInputs)
      owner.m_k6EconomyInputs = Own(new Inputs());
    if (!owner.m_k6QuotaCrypto)
      owner.m_k6QuotaCrypto = Own(new CKad6QuotaCrypto());
    if (!owner.m_k6QuotaCertificate)
      owner.m_k6QuotaCertificate = Own(new kad6::K6QuotaIssuerCertificate());
    if (!owner.m_k6QuotaCertificateWire)
      owner.m_k6QuotaCertificateWire = Own(new std::vector<std::uint8_t>());
    if (!owner.m_k6QuotaIssuerLimiter)
      owner.m_k6QuotaIssuerLimiter = Own(new kad6::K6QuotaIssuerLimiter());
    if (!owner.m_k6QuotaHierarchy)
      owner.m_k6QuotaHierarchy = Own(new kad6::K6QuotaHierarchy());
    if (!owner.m_k6QuotaSpent)
      owner.m_k6QuotaSpent = Own(new kad6::K6QuotaSpentSet());
    if (!owner.m_k6QuotaGrants)
      owner.m_k6QuotaGrants = Own(new Grants());
  }
  static bool CanAdmit(const LiveTunnelQuotaAuthority &owner,
                       kad6::K6Service service) noexcept {
    return owner.m_k6Hardening &&
           static_cast<const kad6::K6HardeningController *>(
               owner.m_k6Hardening.get())
               ->CanAdmit(service);
  }
  static bool SetEnabled(LiveTunnelQuotaAuthority &owner,
                         kad6::K6Service service, bool enabled,
                         std::uint64_t now, std::uint32_t drain,
                         std::uint64_t active) {
    return static_cast<kad6::K6HardeningController *>(owner.m_k6Hardening.get())
        ->SetEnabled(service, enabled, now, drain, active);
  }
  static kad6::K6HardeningSnapshot
  Snapshot(const LiveTunnelQuotaAuthority &owner) noexcept {
    return owner.m_k6Hardening
               ? static_cast<const kad6::K6HardeningController *>(
                     owner.m_k6Hardening.get())
                     ->Snapshot()
               : kad6::K6HardeningSnapshot();
  }
  static kad6::K6DrainResult
  Tick(LiveTunnelQuotaAuthority &owner, std::uint64_t now,
       const std::array<std::uint64_t,
                        static_cast<size_t>(kad6::K6Service::Count)> &active) {
    return static_cast<kad6::K6HardeningController *>(owner.m_k6Hardening.get())
        ->Tick(now, active);
  }
  static kad6::K6EconomyTelemetry *
  Telemetry(LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<kad6::K6EconomyTelemetry *>(
        owner.m_k6EconomyTelemetry.get());
  }
  static Inputs *InputsFor(LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<Inputs *>(owner.m_k6EconomyInputs.get());
  }
  static void RecordUsefulBytes(LiveTunnelQuotaAuthority &owner,
                                std::uint64_t delta) noexcept {
    std::lock_guard<std::mutex> lock(owner.m_k6EconomyMutex);
    owner.m_k6EconomyUsefulBytes += delta;
  }
  static void RecordPublishAttempt(LiveTunnelQuotaAuthority &owner,
                                   std::uint64_t delta) noexcept {
    std::lock_guard<std::mutex> lock(owner.m_k6EconomyMutex);
    owner.m_k6EconomyPublishAttempts += delta;
  }
  static bool EconomyHealthy(const LiveTunnelQuotaAuthority &owner) noexcept {
    std::lock_guard<std::mutex> lock(owner.m_k6EconomyMutex);
    if (!owner.m_k6EconomyReady || !owner.m_k6EconomyInputs ||
        !owner.m_k6EconomyTelemetry)
      return false;
    const Inputs *inputs =
        static_cast<const Inputs *>(owner.m_k6EconomyInputs.get());
    for (const kad6::K6SaturationInputs &input : *inputs) {
      const double rho = kad6::K6Rho(input);
      if (!std::isfinite(rho) || rho >= kad6::kK6RhoTarget)
        return false;
    }
    return true;
  }
  static bool EconomyAdmit(LiveTunnelQuotaAuthority &owner,
                           kad6::K6Service service, std::uint64_t now) {
    std::lock_guard<std::mutex> lock(owner.m_k6EconomyMutex);
    const size_t index = static_cast<size_t>(service);
    Inputs *inputs = InputsFor(owner);
    if (index >= inputs->size())
      return false;
    const double rho = owner.m_k6EconomyReady
                           ? kad6::K6Rho((*inputs)[index])
                           : std::numeric_limits<double>::infinity();
    const bool admitted =
        owner.m_k6EconomyReady && kad6::K6AdmitLease((*inputs)[index]);
    Telemetry(owner)->Observe(static_cast<kad6::Byte>(index), now, rho, true,
                              admitted);
    return admitted;
  }
  static void EconomyRates(LiveTunnelQuotaAuthority &owner, std::uint64_t now,
                           double usefulCapacity, std::uint64_t processNow,
                           std::uint64_t systemNow, double &demandedBps,
                           double &publishQps, double &processCpu) {
    (void)usefulCapacity;
    const std::uint64_t elapsed =
        owner.m_k6EconomyLastSampleAt && now > owner.m_k6EconomyLastSampleAt
            ? now - owner.m_k6EconomyLastSampleAt
            : 1;
    const std::uint64_t bytes =
        owner.m_k6EconomyUsefulBytes >= owner.m_k6EconomyLastUsefulBytes
            ? owner.m_k6EconomyUsefulBytes - owner.m_k6EconomyLastUsefulBytes
            : 0;
    const std::uint64_t publishes =
        owner.m_k6EconomyPublishAttempts >= owner.m_k6EconomyLastPublishAttempts
            ? owner.m_k6EconomyPublishAttempts -
                  owner.m_k6EconomyLastPublishAttempts
            : 0;
    demandedBps =
        static_cast<double>(bytes) * 8.0 / static_cast<double>(elapsed);
    publishQps = static_cast<double>(publishes) / static_cast<double>(elapsed);
    processCpu = 0.0;
    if (owner.m_k6EconomyLastProcessCpu &&
        systemNow > owner.m_k6EconomyLastSystemCpu &&
        processNow >= owner.m_k6EconomyLastProcessCpu)
      processCpu = (std::min)(
          1.0,
          static_cast<double>(processNow - owner.m_k6EconomyLastProcessCpu) /
              static_cast<double>(systemNow - owner.m_k6EconomyLastSystemCpu));
    owner.m_k6EconomyLastProcessCpu = processNow;
    owner.m_k6EconomyLastSystemCpu = systemNow;
  }
  static void UpdateEconomyInputs(
      LiveTunnelQuotaAuthority &owner, std::uint64_t now,
      const std::array<std::uint64_t,
                       static_cast<size_t>(kad6::K6Service::Count)> &active,
      double capacity, double demanded, double publish, double cpu,
      std::uint64_t occupied) {
    Inputs *inputs = InputsFor(owner);
    for (size_t i = 0; i < inputs->size(); ++i) {
      kad6::K6SaturationInputs input;
      input.demanded_useful_bps =
          (i == static_cast<size_t>(kad6::K6Service::ExitEd2kDial) ||
           i == static_cast<size_t>(kad6::K6Service::ExitEd2kFull))
              ? demanded
              : 0.0;
      input.available_useful_bps = capacity;
      input.overhead_factor = 1.15;
      input.active_streams = active[i];
      input.available_stream_slots =
          i == static_cast<size_t>(kad6::K6Service::ExitKad) ? 4096u : 512u;
      input.occupied_preauth_slots =
          i == static_cast<size_t>(kad6::K6Service::ExitEd2kFull) ? occupied
                                                                  : 0;
      input.available_preauth_slots = kad6::kK6PreAuthMaxSlots;
      input.demanded_publish_qps =
          i == static_cast<size_t>(kad6::K6Service::ExitKad) ? publish : 0.0;
      input.available_publish_qps = 2.0;
      input.measured_exit_cpu = cpu;
      input.exit_cpu_budget = .85;
      (*inputs)[i] = input;
      Telemetry(owner)->Observe(static_cast<kad6::Byte>(i), now,
                                kad6::K6Rho(input), false, false);
    }
    Telemetry(owner)->SealThrough(now);
    owner.m_k6EconomyLastUsefulBytes = owner.m_k6EconomyUsefulBytes;
    owner.m_k6EconomyLastPublishAttempts = owner.m_k6EconomyPublishAttempts;
    owner.m_k6EconomyLastSampleAt = now;
    owner.m_k6EconomyReady = capacity > 0.0;
  }
  static void RefreshEconomy(
      LiveTunnelQuotaAuthority &owner, std::uint64_t now,
      const std::array<std::uint64_t,
                       static_cast<size_t>(kad6::K6Service::Count)> &active,
      double capacity, std::uint64_t processNow, std::uint64_t systemNow,
      std::uint64_t occupied) {
    std::lock_guard<std::mutex> lock(owner.m_k6EconomyMutex);
    double demanded = 0, publish = 0, cpu = 0;
    EconomyRates(owner, now, capacity, processNow, systemNow, demanded, publish,
                 cpu);
    UpdateEconomyInputs(owner, now, active, capacity, demanded, publish, cpu,
                        occupied);
  }
  static void FillEconomySnapshot(const LiveTunnelQuotaAuthority &owner,
                                  bool &measurementReady,
                                  std::array<double, static_cast<size_t>(
                                      kad6::K6Service::Count)> &rho,
                                  std::array<kad6::K6EconomyWindowSnapshot,
                                      static_cast<size_t>(
                                          kad6::K6Service::Count)> &economy) {
    std::lock_guard<std::mutex> lock(owner.m_k6EconomyMutex);
    measurementReady = owner.m_k6EconomyReady;
    const Inputs *inputs =
        static_cast<const Inputs *>(owner.m_k6EconomyInputs.get());
    const kad6::K6EconomyTelemetry *telemetry =
        static_cast<const kad6::K6EconomyTelemetry *>(
            owner.m_k6EconomyTelemetry.get());
    for (size_t i = 0; inputs && telemetry && i < economy.size(); ++i) {
      rho[i] = owner.m_k6EconomyReady
                   ? kad6::K6Rho((*inputs)[i])
                   : std::numeric_limits<double>::infinity();
      economy[i] = telemetry->Latest(static_cast<kad6::Byte>(i));
    }
  }
  static CKad6QuotaCrypto *
  QuotaCrypto(LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<CKad6QuotaCrypto *>(owner.m_k6QuotaCrypto.get());
  }
  static const CKad6QuotaCrypto *
  QuotaCrypto(const LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<const CKad6QuotaCrypto *>(owner.m_k6QuotaCrypto.get());
  }
  static kad6::K6QuotaIssuerCertificate *
  QuotaCertificate(LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<kad6::K6QuotaIssuerCertificate *>(
        owner.m_k6QuotaCertificate.get());
  }
  static std::vector<std::uint8_t> *
  QuotaCertificateWire(LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<std::vector<std::uint8_t> *>(
        owner.m_k6QuotaCertificateWire.get());
  }
  static const std::vector<std::uint8_t> *
  QuotaCertificateWire(const LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<const std::vector<std::uint8_t> *>(
        owner.m_k6QuotaCertificateWire.get());
  }
  static kad6::K6QuotaIssuerLimiter *
  QuotaIssuerLimiter(LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<kad6::K6QuotaIssuerLimiter *>(
        owner.m_k6QuotaIssuerLimiter.get());
  }
  static kad6::K6QuotaHierarchy *
  QuotaHierarchy(LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<kad6::K6QuotaHierarchy *>(
        owner.m_k6QuotaHierarchy.get());
  }
  static kad6::K6QuotaSpentSet *
  QuotaSpent(LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<kad6::K6QuotaSpentSet *>(owner.m_k6QuotaSpent.get());
  }
  static Grants *QuotaGrants(LiveTunnelQuotaAuthority &owner) noexcept {
    return static_cast<Grants *>(owner.m_k6QuotaGrants.get());
  }
  static std::string GrantKey(std::uint32_t circuitId,
                              const kad6::Hash32 &context) {
    std::string key(sizeof circuitId + context.size(), '\0');
    memcpy(&key[0], &circuitId, sizeof circuitId);
    memcpy(&key[sizeof circuitId], context.data(), context.size());
    return key;
  }
  static void ResetQuotaState(LiveTunnelQuotaAuthority &owner) {
    std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
    owner.m_k6QuotaIssuerLimiter = Own(new kad6::K6QuotaIssuerLimiter());
    owner.m_k6QuotaHierarchy = Own(new kad6::K6QuotaHierarchy());
    owner.m_k6QuotaSpent = Own(new kad6::K6QuotaSpentSet());
    QuotaGrants(owner)->clear();
  }
  static std::vector<std::uint64_t>
  PruneQuotaGrants(LiveTunnelQuotaAuthority &owner, std::uint64_t now) {
    std::vector<std::uint64_t> released;
    std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
    Grants *grants = QuotaGrants(owner);
    for (auto it = grants->begin(); it != grants->end();) {
      if (it->second.expires_at <= now) {
        released.push_back(it->second.allocation_id);
        it = grants->erase(it);
      } else {
        ++it;
      }
    }
    return released;
  }
  static bool
  EnsureQuotaAuthority(LiveTunnelQuotaAuthority &owner, std::uint64_t now,
                       const std::string &storagePath,
                       const std::uint8_t nodePublicKey[32],
                       const kad6::Kad6CryptoHooks &identityCrypto) {
    if (now == 0 || storagePath.empty() || !nodePublicKey)
      return false;
    const std::uint64_t epoch = kad6::K6QuotaEpoch(now);
    kad6::K6QuotaIssuerCertificate candidate;
    bool certificateNeeded = false;
    {
      std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
      CKad6QuotaCrypto *crypto = QuotaCrypto(owner);
      if (!crypto->Ready()) {
        if (owner.m_k6QuotaInitAttempted)
          return false;
        owner.m_k6QuotaInitAttempted = true;
        if (!crypto->Initialize(storagePath, 4096) || !crypto->Persistent())
          return false;
      }
      std::vector<std::uint8_t> *wire = QuotaCertificateWire(owner);
      certificateNeeded =
          owner.m_k6QuotaCertificateEpoch != epoch || wire->empty();
      if (certificateNeeded) {
        candidate.key = crypto->PublicKey();
        memcpy(candidate.issuer_node_pub.data(), nodePublicKey,
               candidate.issuer_node_pub.size());
        candidate.policy_id = 1;
        candidate.service_mask = 0x0F;
        candidate.valid_from_epoch = epoch;
        candidate.valid_until_epoch = epoch + 1;
      }
    }
    if (certificateNeeded) {
      std::vector<std::uint8_t> encoded;
      if (kad6::SignK6QuotaIssuerCertificate(identityCrypto, candidate,
                                             encoded) != kad6::Kad6Status::Ok)
        return false;
      std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
      std::vector<std::uint8_t> *wire = QuotaCertificateWire(owner);
      if (owner.m_k6QuotaCertificateEpoch != epoch || wire->empty()) {
        *QuotaCertificate(owner) = std::move(candidate);
        *wire = std::move(encoded);
        owner.m_k6QuotaCertificateEpoch = epoch;
      }
    }
    {
      std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
      QuotaIssuerLimiter(owner)->Prune(epoch);
      QuotaSpent(owner)->Prune(epoch);
    }
    return true;
  }
  static bool CopyQuotaCertificateWire(const LiveTunnelQuotaAuthority &owner,
                                       std::vector<std::uint8_t> &out) {
    std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
    const std::vector<std::uint8_t> *wire = QuotaCertificateWire(owner);
    if (!wire || wire->empty())
      return false;
    out = *wire;
    return true;
  }
  static bool BlindQuotaToken(LiveTunnelQuotaAuthority &owner,
                              const kad6::K6QuotaIssuerCertificate &certificate,
                              const kad6::K6QuotaToken &token,
                              kad6::K6QuotaBlindState &blind) {
    kad6::K6QuotaCryptoHooks hooks;
    {
      std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
      hooks = QuotaCrypto(owner)->Hooks();
    }
    return kad6::BlindK6QuotaToken(hooks, certificate.key, token, blind) ==
           kad6::Kad6Status::Ok;
  }
  static bool
  FinalizeQuotaToken(LiveTunnelQuotaAuthority &owner,
                     const kad6::K6QuotaIssuerCertificate &certificate,
                     const kad6::K6QuotaBlindState &blind,
                     const std::vector<std::uint8_t> &blindSignature,
                     kad6::K6QuotaPresentation &presentation) {
    kad6::K6QuotaCryptoHooks hooks;
    {
      std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
      hooks = QuotaCrypto(owner)->Hooks();
    }
    return kad6::FinalizeK6QuotaToken(hooks, certificate, blind, blindSignature,
                                      presentation) == kad6::Kad6Status::Ok;
  }
  static void IssueQuota(LiveTunnelQuotaAuthority &owner,
                         const kad6::K6QuotaBlindRequest &request,
                         const std::array<std::uint8_t, 32> &principal,
                         const std::array<std::uint8_t, 6> &prefix48,
                         std::uint32_t asn, std::uint64_t now,
                         std::uint64_t monotonicNowMs,
                         kad6::K6QuotaBlindResponse &response) {
    response = kad6::K6QuotaBlindResponse();
    response.status = kad6::K6QuotaStatus::PolicyDenied;
    kad6::K6QuotaCryptoHooks hooks;
    std::vector<std::uint8_t> certificateWire;
    {
      std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
      const kad6::K6QuotaIssuerCertificate *certificate =
          QuotaCertificate(owner);
      if (!certificate || !kad6::Kad6CtEqual(request.issuer_key_id.data(),
                                             certificate->key_id.data(),
                                             request.issuer_key_id.size())) {
        response.status = kad6::K6QuotaStatus::UnknownIssuer;
        return;
      }
      if (request.version == 2 &&
          request.subepoch_slot != kad6::K6QuotaSubepoch(now)) {
        response.status = kad6::K6QuotaStatus::WrongEpoch;
        return;
      }
      const std::uint64_t epoch = kad6::K6QuotaEpoch(now);
      if (request.version == 1) {
        response.status = QuotaIssuerLimiter(owner)->Reserve(
            principal, epoch, request.blinded_messages.size());
      } else {
        kad6::K6QuotaHierarchyRequest budget;
        budget.principal = principal;
        budget.prefix48 = prefix48;
        budget.issuer_key_id = request.issuer_key_id;
        budget.asn = asn;
        budget.service = request.service;
        budget.now_ms = monotonicNowMs;
        budget.units = request.blinded_messages.size();
        response.status = QuotaHierarchy(owner)->Reserve(budget);
      }
      if (response.status != kad6::K6QuotaStatus::Ok)
        return;
      hooks = QuotaCrypto(owner)->Hooks();
      certificateWire = *QuotaCertificateWire(owner);
    }
    response.blind_signatures.reserve(request.blinded_messages.size());
    for (const std::vector<std::uint8_t> &blinded : request.blinded_messages) {
      std::vector<std::uint8_t> signature;
      if (!hooks.blind_sign ||
          !hooks.blind_sign(hooks.context, request.issuer_key_id,
                            blinded.data(), blinded.size(), signature)) {
        response.status = kad6::K6QuotaStatus::CryptoFailure;
        response.blind_signatures.clear();
        return;
      }
      response.blind_signatures.push_back(std::move(signature));
    }
    response.issuer_certificate = std::move(certificateWire);
  }
  static void PrepareQuotaPresentation(
      LiveTunnelQuotaAuthority &owner,
      const kad6::K6QuotaPresentation &presentation, bool issuerTrusted,
      std::uint32_t circuitId, std::uint64_t now,
      const kad6::Kad6CryptoHooks &identityCrypto,
      kad6::K6QuotaPresentationResult &result, PendingGrant &pending) {
    result = kad6::K6QuotaPresentationResult();
    result.status = kad6::K6QuotaStatus::BadRequest;
    pending = PendingGrant();
    kad6::K6QuotaToken token;
    kad6::K6QuotaIssuerCertificate certificate;
    std::size_t consumed = 0;
    if (kad6::DecodeK6QuotaPreparedMessage(presentation.prepared_message.data(),
                                           presentation.prepared_message.size(),
                                           token) != kad6::Kad6Status::Ok ||
        kad6::DecodeK6QuotaIssuerCertificate(
            presentation.issuer_certificate.data(),
            presentation.issuer_certificate.size(), certificate,
            &consumed) != kad6::Kad6Status::Ok ||
        consumed != presentation.issuer_certificate.size()) {
      result.status = kad6::K6QuotaStatus::InvalidProof;
      return;
    }
    kad6::K6QuotaCryptoHooks quotaCrypto;
    {
      std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
      quotaCrypto = QuotaCrypto(owner)->Hooks();
    }
    result.status = kad6::VerifyK6QuotaPresentation(
        identityCrypto, quotaCrypto, presentation, token.service,
        token.policy_id, kad6::K6QuotaEpoch(now), kad6::K6QuotaSubepoch(now),
        token.presentation_context_hash, issuerTrusted, &token, &certificate);
    if (result.status != kad6::K6QuotaStatus::Ok)
      return;
    if (!identityCrypto.sha256 ||
        !identityCrypto.sha256(token.admission_unit.data(),
                               token.admission_unit.size(),
                               result.admission_unit_hash.data())) {
      result.status = kad6::K6QuotaStatus::CryptoFailure;
      return;
    }
    std::uint64_t allocation = 0;
    for (unsigned i = 0; i < 8; ++i)
      allocation |= static_cast<std::uint64_t>(result.admission_unit_hash[i])
                    << (8 * i);
    if (allocation == 0)
      allocation = 1;
    pending.key = GrantKey(circuitId, token.presentation_context_hash);
    {
      std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
      result.status = QuotaSpent(owner)->Consume(
          token.valid_epoch, token.admission_unit, kad6::K6QuotaEpoch(now));
      if (result.status != kad6::K6QuotaStatus::Ok)
        return;
      Grants *grants = QuotaGrants(owner);
      if (grants->size() >= kad6::kK6QuotaDefaultSpentCapacity ||
          grants->find(pending.key) != grants->end()) {
        result.status = kad6::K6QuotaStatus::Capacity;
        return;
      }
    }
    pending.grant.service = token.service;
    pending.grant.context = token.presentation_context_hash;
    pending.grant.issuer = certificate.key_id;
    pending.grant.allocation_id = allocation;
    pending.grant.expires_at =
        token.version == 2
            ? token.valid_epoch * kad6::kK6QuotaEpochSeconds +
                  (static_cast<std::uint64_t>(token.subepoch_slot) + 1) *
                      kad6::kK6QuotaSubepochSeconds
            : (token.valid_epoch + 1) * kad6::kK6QuotaEpochSeconds;
    pending.ready = true;
    result.valid_epoch = token.valid_epoch;
  }
  static bool CommitQuotaGrant(LiveTunnelQuotaAuthority &owner,
                               const PendingGrant &pending) {
    std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
    Grants *grants = QuotaGrants(owner);
    if (!pending.ready || !grants ||
        grants->size() >= kad6::kK6QuotaDefaultSpentCapacity ||
        grants->find(pending.key) != grants->end())
      return false;
    (*grants)[pending.key] = pending.grant;
    return true;
  }
  static bool ConsumeQuotaGrant(LiveTunnelQuotaAuthority &owner,
                                std::uint32_t circuitId,
                                const kad6::Hash32 &context,
                                std::uint8_t service, std::uint64_t now,
                                bool allowMissing, std::uint64_t &allocation,
                                std::uint64_t &release) {
    allocation = 0;
    release = 0;
    std::lock_guard<std::mutex> lock(owner.m_k6QuotaMutex);
    Grants *grants = QuotaGrants(owner);
    const std::string key = GrantKey(circuitId, context);
    auto found = grants->find(key);
    if (found == grants->end())
      return allowMissing;
    const Grant grant = found->second;
    grants->erase(found);
    if (grant.expires_at <= now ||
        static_cast<std::uint8_t>(grant.service) != service) {
      release = grant.allocation_id;
      return false;
    }
    allocation = grant.allocation_id;
    return true;
  }
};

static LiveTunnelQuotaAuthority *
M2A_LT2_Owner(M2AModuleHandle &handle) noexcept {
  return static_cast<LiveTunnelQuotaAuthority *>(handle.Get());
}
static const LiveTunnelQuotaAuthority *
M2A_LT2_Owner(const M2AModuleHandle &handle) noexcept {
  return static_cast<const LiveTunnelQuotaAuthority *>(handle.Get());
}
void M2A_LT2_InitializeBridge(M2AModuleHandle &handle) {
  if (LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle))
    LiveTunnelQuotaBridge::InitializeBeforePublication(*owner);
}
bool M2A_LT2_HardeningCanAdmitBridge(const M2AModuleHandle &handle,
                                     kad6::K6Service service) noexcept {
  const LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner && LiveTunnelQuotaBridge::CanAdmit(*owner, service);
}
bool M2A_LT2_HardeningSetEnabledBridge(M2AModuleHandle &handle,
                                       kad6::K6Service service, bool enabled,
                                       std::uint64_t now, std::uint32_t drain,
                                       std::uint64_t active) {
  LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner && LiveTunnelQuotaBridge::SetEnabled(*owner, service, enabled,
                                                    now, drain, active);
}
kad6::K6HardeningSnapshot
M2A_LT2_HardeningSnapshotBridge(const M2AModuleHandle &handle) noexcept {
  const LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner ? LiveTunnelQuotaBridge::Snapshot(*owner)
               : kad6::K6HardeningSnapshot();
}
kad6::K6DrainResult M2A_LT2_HardeningTickBridge(
    M2AModuleHandle &handle, std::uint64_t now,
    const std::array<std::uint64_t, static_cast<size_t>(kad6::K6Service::Count)>
        &active) {
  LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner ? LiveTunnelQuotaBridge::Tick(*owner, now, active)
               : kad6::K6DrainResult();
}
void M2A_LT2_RecordUsefulBytesBridge(M2AModuleHandle &handle,
                                     std::uint64_t delta) noexcept {
  if (LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle))
    LiveTunnelQuotaBridge::RecordUsefulBytes(*owner, delta);
}
void M2A_LT2_RecordPublishAttemptBridge(M2AModuleHandle &handle,
                                        std::uint64_t delta) noexcept {
  if (LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle))
    LiveTunnelQuotaBridge::RecordPublishAttempt(*owner, delta);
}
bool M2A_LT2_EconomyHealthyBridge(const M2AModuleHandle &handle) noexcept {
  const LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner && LiveTunnelQuotaBridge::EconomyHealthy(*owner);
}
bool M2A_LT2_EconomyAdmitBridge(M2AModuleHandle &handle,
                                kad6::K6Service service, std::uint64_t now) {
  LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner && LiveTunnelQuotaBridge::EconomyAdmit(*owner, service, now);
}
void M2A_LT2_RefreshEconomyBridge(
    M2AModuleHandle &handle, std::uint64_t now,
    const std::array<std::uint64_t, static_cast<size_t>(kad6::K6Service::Count)>
        &active,
    double capacity, std::uint64_t processNow, std::uint64_t systemNow,
    std::uint64_t occupied) {
  if (LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle))
    LiveTunnelQuotaBridge::RefreshEconomy(*owner, now, active, capacity,
                                          processNow, systemNow, occupied);
}
void M2A_LT2_FillEconomySnapshotBridge(
    const M2AModuleHandle &handle, bool &measurementReady,
    std::array<double, static_cast<size_t>(kad6::K6Service::Count)> &rho,
    std::array<kad6::K6EconomyWindowSnapshot,
        static_cast<size_t>(kad6::K6Service::Count)> &economy) {
  if (const LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle))
    LiveTunnelQuotaBridge::FillEconomySnapshot(
        *owner, measurementReady, rho, economy);
}
void M2A_LT2_ResetQuotaStateBridge(M2AModuleHandle &handle) {
  if (LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle))
    LiveTunnelQuotaBridge::ResetQuotaState(*owner);
}
std::vector<std::uint64_t>
M2A_LT2_PruneQuotaGrantsBridge(M2AModuleHandle &handle, std::uint64_t now) {
  if (LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle))
    return LiveTunnelQuotaBridge::PruneQuotaGrants(*owner, now);
  return {};
}
bool M2A_LT2_EnsureQuotaAuthorityBridge(
    M2AModuleHandle &handle, std::uint64_t now, const std::string &storagePath,
    const std::uint8_t nodePublicKey[32],
    const kad6::Kad6CryptoHooks &identityCrypto) {
  LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner && LiveTunnelQuotaBridge::EnsureQuotaAuthority(
                      *owner, now, storagePath, nodePublicKey, identityCrypto);
}
bool M2A_LT2_QuotaCertificateWireBridge(const M2AModuleHandle &handle,
                                        std::vector<std::uint8_t> &out) {
  const LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner && LiveTunnelQuotaBridge::CopyQuotaCertificateWire(*owner, out);
}
bool M2A_LT2_BlindQuotaTokenBridge(
    M2AModuleHandle &handle, const kad6::K6QuotaIssuerCertificate &certificate,
    const kad6::K6QuotaToken &token, kad6::K6QuotaBlindState &blind) {
  LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner && LiveTunnelQuotaBridge::BlindQuotaToken(*owner, certificate,
                                                         token, blind);
}
bool M2A_LT2_FinalizeQuotaTokenBridge(
    M2AModuleHandle &handle, const kad6::K6QuotaIssuerCertificate &certificate,
    const kad6::K6QuotaBlindState &blind,
    const std::vector<std::uint8_t> &blindSignature,
    kad6::K6QuotaPresentation &presentation) {
  LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner && LiveTunnelQuotaBridge::FinalizeQuotaToken(
                      *owner, certificate, blind, blindSignature, presentation);
}
void M2A_LT2_IssueQuotaBridge(M2AModuleHandle &handle,
                              const kad6::K6QuotaBlindRequest &request,
                              const std::array<std::uint8_t, 32> &principal,
                              const std::array<std::uint8_t, 6> &prefix48,
                              std::uint32_t asn, std::uint64_t now,
                              std::uint64_t monotonicNowMs,
                              kad6::K6QuotaBlindResponse &response) {
  if (LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle))
    LiveTunnelQuotaBridge::IssueQuota(*owner, request, principal, prefix48, asn,
                                      now, monotonicNowMs, response);
}
using M2ARegisterFairAllocation = bool (*)(void *, std::uint64_t,
                                           const kad6::Hash32 &, std::uint64_t,
                                           std::uint64_t);
using M2AReleaseFairAllocation = void (*)(void *, std::uint64_t);
void M2A_LT2_PresentQuotaBridge(M2AModuleHandle &handle,
                                const kad6::K6QuotaPresentation &presentation,
                                bool issuerTrusted, std::uint32_t circuitId,
                                std::uint64_t now,
                                const kad6::Kad6CryptoHooks &identityCrypto,
                                void *fairContext,
                                M2ARegisterFairAllocation registerFair,
                                M2AReleaseFairAllocation releaseFair,
                                kad6::K6QuotaPresentationResult &result) {
  LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  if (!owner) {
    result.status = kad6::K6QuotaStatus::CryptoFailure;
    return;
  }
  LiveTunnelQuotaBridge::PendingGrant pending;
  LiveTunnelQuotaBridge::PrepareQuotaPresentation(
      *owner, presentation, issuerTrusted, circuitId, now, identityCrypto,
      result, pending);
  if (!pending.ready)
    return;
  if (!registerFair ||
      !registerFair(fairContext, pending.grant.allocation_id,
                    pending.grant.issuer, 4ull * 1024ull * 1024ull * 1024ull,
                    16ull * 4ull * 1024ull * 1024ull * 1024ull)) {
    result.status = kad6::K6QuotaStatus::Capacity;
    result.valid_epoch = 0;
    return;
  }
  if (!LiveTunnelQuotaBridge::CommitQuotaGrant(*owner, pending)) {
    if (releaseFair)
      releaseFair(fairContext, pending.grant.allocation_id);
    result.status = kad6::K6QuotaStatus::Capacity;
    result.valid_epoch = 0;
  }
}
bool M2A_LT2_ConsumeQuotaGrantBridge(
    M2AModuleHandle &handle, std::uint32_t circuitId,
    const std::array<std::uint8_t, 32> &context, std::uint8_t service,
    std::uint64_t now, bool allowMissing, std::uint64_t &allocation,
    std::uint64_t &release) {
  LiveTunnelQuotaAuthority *owner = M2A_LT2_Owner(handle);
  return owner && LiveTunnelQuotaBridge::ConsumeQuotaGrant(
                      *owner, circuitId, context, service, now, allowMissing,
                      allocation, release);
}
} // namespace eSELive
