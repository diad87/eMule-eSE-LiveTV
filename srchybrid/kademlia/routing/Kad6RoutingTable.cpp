#include "stdafx.h"
#include "Kad6RoutingTable.h"

#include "Kad6CryptoHost.h"
#include "Preferences.h"
#include "eMuleAI/Address.h"
#include "Log.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/Prefs.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <vector>

namespace Kademlia
{
namespace
{
	const std::size_t KAD6_NO_INDEX = static_cast<std::size_t>(-1);
	const std::uint64_t KAD6_PROBATION_TTL = 24ull * 60 * 60;
	const std::uint64_t KAD6_VERIFIED_TTL = 7ull * 24 * 60 * 60;
	const std::size_t KAD6_BUCKET_SIZE = 10;

	bool SameId(const kad6::KadId& a, const kad6::KadId& b)
	{
		return std::memcmp(a.data(), b.data(), a.size()) == 0;
	}

	bool IsZeroId(const kad6::KadId& id)
	{
		kad6::Byte value = 0;
		for (kad6::Byte part : id)
			value = static_cast<kad6::Byte>(value | part);
		return value == 0;
	}

	bool SameEndpoint(const kad6::K6Endpoint& a, const kad6::K6Endpoint& b)
	{
		return a.addr == b.addr && a.udp_port == b.udp_port
			&& a.tcp_port == b.tcp_port
			&& a.transport_flags == b.transport_flags
			&& a.priority == b.priority && a.observed == b.observed
			&& a.valid_until == b.valid_until;
	}

	bool SamePub(const kad6::Ed25519Pub& a, const kad6::Ed25519Pub& b)
	{
		return std::memcmp(a.data(), b.data(), a.size()) == 0;
	}

	bool SameSignature(const kad6::Ed25519Sig& a, const kad6::Ed25519Sig& b)
	{
		return std::memcmp(a.data(), b.data(), a.size()) == 0;
	}

	bool IsPublicV6(const kad6::Kad6Address& address)
	{
		if (address.family != kad6::Kad6Address::Family::IPv6)
			return false;
		CAddress hostAddress(address.addr.data());
		return hostAddress.GetType() == CAddress::IPv6
			&& hostAddress.IsPublicIP();
	}

	bool IsPublicV4(const kad6::Kad6Address& address)
	{
		if (address.family != kad6::Kad6Address::Family::IPv4)
			return false;
		uint32 networkAddress = 0;
		std::memcpy(&networkAddress, address.addr.data(), sizeof networkAddress);
		const CAddress hostAddress(networkAddress, false);
		return hostAddress.GetType() == CAddress::IPv4
			&& hostAddress.IsPublicIP();
	}

	bool IsPublicAddress(const kad6::Kad6Address& address)
	{
		kad6::Kad6Address normalized = address;
		kad6::Kad6AddressNormalize(normalized);
		return IsPublicV6(normalized) || IsPublicV4(normalized);
	}

	bool IsDirectRouteAddress(const kad6::Kad6Address& address)
	{
		kad6::Kad6Address normalized = address;
		kad6::Kad6AddressNormalize(normalized);
		if (IsPublicV6(normalized) || IsPublicV4(normalized))
			return true;
		if (normalized.family != kad6::Kad6Address::Family::IPv6)
			return false;
		const CAddress hostAddress(normalized.addr.data());
		if (hostAddress.GetType() != CAddress::IPv6
			|| !hostAddress.IsUniqueLocalIPv6())
			return false;
		LPCTSTR configured = thePrefs.GetIPv6BindAddr();
		if (configured == NULL || configured[0] == 0
			|| _tcscmp(configured, _T("::")) == 0)
			return false;
		const CAddress configuredV6(configured, false);
		return configuredV6.GetType() == CAddress::IPv6
			&& configuredV6.IsUniqueLocalIPv6();
	}

	CKad6RoutingTable::Entry::Candidate* FindCandidate(
		CKad6RoutingTable::Entry& entry, const kad6::K6Endpoint& endpoint)
	{
		for (CKad6RoutingTable::Entry::Candidate& candidate : entry.candidates)
			if (SameEndpoint(candidate.endpoint, endpoint))
				return &candidate;
		return NULL;
	}

	const CKad6RoutingTable::Entry::Candidate* FindCandidate(
		const CKad6RoutingTable::Entry& entry, const kad6::K6Endpoint& endpoint)
	{
		for (const CKad6RoutingTable::Entry::Candidate& candidate : entry.candidates)
			if (SameEndpoint(candidate.endpoint, endpoint))
				return &candidate;
		return NULL;
	}

	void SelectBestVerifiedCandidate(CKad6RoutingTable::Entry& entry)
	{
		const CKad6RoutingTable::Entry::Candidate* best = NULL;
		for (const CKad6RoutingTable::Entry::Candidate& candidate : entry.candidates) {
			if (!candidate.verified)
				continue;
			if (best == NULL
				|| (candidate.endpoint.addr.family == kad6::Kad6Address::Family::IPv6
					&& best->endpoint.addr.family != kad6::Kad6Address::Family::IPv6)
				|| (candidate.endpoint.addr.family == best->endpoint.addr.family
					&& (candidate.failures < best->failures
						|| (candidate.failures == best->failures
							&& candidate.endpoint.priority < best->endpoint.priority))))
				best = &candidate;
		}
		entry.verified = best != NULL;
		if (best != NULL) {
			entry.contact.endpoint = best->endpoint;
			entry.lastSeen = best->lastSeen;
			entry.failures = best->failures;
		}
	}

	CString SnapshotPath()
	{
		return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("nodes_v6.dat");
	}

	CString AsnPath()
	{
		return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_asn.dat");
	}

	CString PathEvidencePath()
	{
		return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_path_evidence.dat");
	}

	CString BootstrapPath()
	{
		return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_bootstrap.dat");
	}

	CString BootstrapPubPath()
	{
		return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_bootstrap.pub");
	}

	CString BootstrapSequencePath()
	{
		return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_bootstrap.seq");
	}

	bool ReadBoundedFile(const CString& path, std::size_t maximum,
		std::vector<kad6::Byte>& bytes)
	{
		bytes.clear();
		try {
			CFile file;
			if (!file.Open(path, CFile::modeRead | CFile::shareDenyWrite))
				return false;
			const ULONGLONG length = file.GetLength();
			if (length == 0 || length > maximum || length > UINT_MAX) {
				file.Close();
				return false;
			}
			bytes.resize(static_cast<std::size_t>(length));
			const bool ok = file.Read(bytes.data(), static_cast<UINT>(bytes.size()))
				== bytes.size();
			file.Close();
			if (!ok)
				bytes.clear();
			return ok;
		}
		catch (CFileException* error) {
			error->Delete();
			bytes.clear();
			return false;
		}
	}

	bool LoadBootstrapSequence(std::uint64_t& sequence)
	{
		sequence = 0;
		std::vector<kad6::Byte> bytes;
		if (!ReadBoundedFile(BootstrapSequencePath(), 16, bytes))
			return false;
		if (bytes.size() != 16 || bytes[0] != 'K' || bytes[1] != '6'
			|| bytes[2] != 'S' || bytes[3] != 'Q' || bytes[4] != 1
			|| bytes[5] != 0 || bytes[6] != 0 || bytes[7] != 0)
			return false;
		for (std::size_t i = 0; i < 8; ++i)
			sequence |= static_cast<std::uint64_t>(bytes[8 + i]) << (8 * i);
		return sequence != 0;
	}

	bool SaveBootstrapSequence(std::uint64_t sequence)
	{
		if (sequence == 0)
			return false;
		kad6::Byte bytes[16] = {'K', '6', 'S', 'Q', 1, 0, 0, 0};
		for (std::size_t i = 0; i < 8; ++i)
			bytes[8 + i] = static_cast<kad6::Byte>(sequence >> (8 * i));
		const CString path = BootstrapSequencePath();
		const CString temporary = path + _T(".new");
		try {
			CFile file(temporary, CFile::modeCreate | CFile::modeWrite
				| CFile::shareExclusive);
			file.Write(bytes, sizeof bytes);
			file.Flush();
			file.Close();
			if (!MoveFileEx(temporary, path,
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
				DeleteFile(temporary);
				return false;
			}
			return true;
		}
		catch (CFileException* error) {
			error->Delete();
			DeleteFile(temporary);
			return false;
		}
	}

	bool RecordCoversContact(const kad6::K6RouterRecord& record,
		const kad6::K6RouteContact& contact)
	{
		if (record.kad_id != contact.node_id || record.epoch != contact.epoch
			|| record.caps != contact.caps)
			return false;
		for (const kad6::K6Endpoint& endpoint : record.endpoints)
			if (SameEndpoint(endpoint, contact.endpoint))
				return true;
		return false;
	}
}

CKad6RoutingTable::CKad6RoutingTable()
{
	if (CKademlia::GetPrefs() != NULL)
		CKademlia::GetPrefs()->GetKadID().ToByteArray(m_localId.data());
	LoadAsnDatabase();
	LoadPathEvidence();
	Load();
	LoadPrivateBootstrap();
}

CKad6RoutingTable::~CKad6RoutingTable()
{
	Save();
}

std::size_t CKad6RoutingTable::FindById(const kad6::KadId& nodeId) const
{
	for (std::size_t i = 0; i < m_entries.size(); ++i)
		if (SameId(m_entries[i].contact.node_id, nodeId))
			return i;
	return KAD6_NO_INDEX;
}

std::size_t CKad6RoutingTable::BucketFor(const kad6::KadId& nodeId) const
{
	for (std::size_t byteIndex = 0; byteIndex < nodeId.size(); ++byteIndex) {
		const kad6::Byte difference = nodeId[byteIndex] ^ m_localId[byteIndex];
		for (unsigned bit = 0; bit < 8; ++bit)
			if ((difference & (0x80u >> bit)) != 0)
				return byteIndex * 8 + bit;
	}
	return KAD6_NO_INDEX; // self
}

bool CKad6RoutingTable::PassesDiversity(
	const kad6::K6RouteContact& contact, std::size_t ignoreIndex) const
{
	if (!IsDirectRouteAddress(contact.endpoint.addr))
		return false;
	kad6::Kad6Address normalizedCandidate = contact.endpoint.addr;
	kad6::Kad6AddressNormalize(normalizedCandidate);
	const CAddress candidateHost(normalizedCandidate.addr.data());
	const bool explicitUlaLab =
		normalizedCandidate.family == kad6::Kad6Address::Family::IPv6
		&& candidateHost.GetType() == CAddress::IPv6
		&& candidateHost.IsUniqueLocalIPv6()
		&& thePrefs.IsEseNetLabContributionActive();

	std::size_t same128 = 0;
	std::size_t same64 = 0;
	std::size_t same56 = 0;
	std::size_t same48 = 0;
	std::size_t sameAsn = 0;
	std::size_t sameOperator = 0;
	kad6::K6AsnInfo candidateInfo;
	const bool candidateAsnKnown = m_asnDatabase.Lookup(
		contact.endpoint.addr, candidateInfo);
	const std::size_t candidateBucket = BucketFor(contact.node_id);
	if (candidateBucket == KAD6_NO_INDEX)
		return false;
	for (std::size_t i = 0; i < m_entries.size(); ++i) {
		if (i == ignoreIndex)
			continue;
		const kad6::Kad6Address& existing = m_entries[i].contact.endpoint.addr;
		if (existing == contact.endpoint.addr)
			++same128;
		if (BucketFor(m_entries[i].contact.node_id) != candidateBucket)
			continue;
		if (existing.family == contact.endpoint.addr.family) {
			const bool ipv4 = existing.family == kad6::Kad6Address::Family::IPv4;
			if (kad6::Kad6AddressInSameSubnet(existing, contact.endpoint.addr,
					ipv4 ? 32 : 64)) ++same64;
			if (kad6::Kad6AddressInSameSubnet(existing, contact.endpoint.addr,
					ipv4 ? 24 : 56)) ++same56;
			if (kad6::Kad6AddressInSameSubnet(existing, contact.endpoint.addr,
					ipv4 ? 20 : 48)) ++same48;
		}
		kad6::K6AsnInfo existingInfo;
		const bool existingAsnKnown = m_asnDatabase.Lookup(existing, existingInfo);
		if ((candidateAsnKnown && existingAsnKnown
				&& existingInfo.asn == candidateInfo.asn)
			|| (!candidateAsnKnown && !existingAsnKnown))
			++sameAsn;
		if (candidateAsnKnown && existingAsnKnown
			&& candidateInfo.operator_group != 0
			&& existingInfo.operator_group == candidateInfo.operator_group)
			++sameOperator;
	}
	// A controlled NetLab places several physical peers in one RFC 4193 /64.
	// Keep exact-address uniqueness, but do not apply public Internet prefix
	// or ASN concentration limits to that explicit-consent private topology.
	if (explicitUlaLab)
		return same128 < 1;
	return same128 < 1 && same64 < 1 && same56 < 2 && same48 < 2
		&& sameAsn < 4 // all unknown-ASN contacts share one fail-closed group
		&& (!candidateAsnKnown || candidateInfo.operator_group == 0
			|| sameOperator < 2);
}

bool CKad6RoutingTable::AddOrUpdate(const kad6::K6RouteContact& contact,
	std::uint64_t nowSeconds, bool verified,
	const kad6::K6RouterRecord* record)
{
	if (nowSeconds == 0 || IsZeroId(contact.node_id) || contact.epoch == 0
		|| contact.endpoint.udp_port == 0
		|| (contact.endpoint.transport_flags & kad6::kK6EpUdpKad6) == 0
		|| (contact.endpoint.transport_flags & kad6::kK6EpReservedMask) != 0
		|| contact.endpoint.observed > 1
		|| (contact.endpoint.valid_until != 0
			&& contact.endpoint.valid_until < nowSeconds)
		|| !IsDirectRouteAddress(contact.endpoint.addr))
		return false;
	if (verified && record == NULL)
		return false;
	if (record != NULL) {
		if (kad6::VerifyK6RouterRecord(MakeKad6HostCryptoHooks(), *record)
				!= kad6::Kad6Status::Ok
			|| !RecordCoversContact(*record, contact)
			|| kad6::K6RouterRecordCheckFresh(*record, nowSeconds)
				!= kad6::Kad6Status::Ok)
			return false;
		for (std::size_t i = 0; i < record->endpoints.size(); ++i) {
			const kad6::K6Endpoint& candidate = record->endpoints[i];
			if (!IsDirectRouteAddress(candidate.addr) || candidate.udp_port == 0
				|| (candidate.transport_flags & kad6::kK6EpUdpKad6) == 0
				|| (candidate.transport_flags & kad6::kK6EpReservedMask) != 0
				|| candidate.observed > 1 || candidate.valid_until < nowSeconds)
				return false;
			for (std::size_t j = i + 1; j < record->endpoints.size(); ++j)
				if (record->endpoints[j].addr == candidate.addr
					&& record->endpoints[j].udp_port == candidate.udp_port)
					return false;
		}
	}

	const std::size_t index = FindById(contact.node_id);
	if (index != KAD6_NO_INDEX) {
		Entry& entry = m_entries[index];
		const bool endpointChanged =
			!SameEndpoint(contact.endpoint, entry.contact.endpoint);
		if (entry.hasSignedIdentity && record == NULL) {
			// An unsigned hint may schedule a challenge only for an endpoint
			// already covered by the pinned signed EndpointSet.
			Entry::Candidate* candidate = FindCandidate(entry, contact.endpoint);
			if (candidate == NULL || contact.epoch != entry.signedEpoch)
				return false;
			candidate->lastSeen = nowSeconds;
			return true;
		}
		if (record != NULL) {
			if (entry.hasSignedIdentity
				&& !SamePub(entry.nodePub, record->node_pub))
				return false; // key rotation requires a future dual-signed cert
			if (entry.hasSignedIdentity && record->epoch < entry.signedEpoch)
				return false;
			if (entry.hasSignedIdentity && record->epoch == entry.signedEpoch
				&& !SameSignature(entry.routerSignature, record->signature))
				return false; // same epoch is an exact signed-record replay only
		} else {
			if (contact.epoch < entry.contact.epoch)
				return false;
			if (contact.epoch == entry.contact.epoch && endpointChanged)
				return false;
			if (entry.verified && endpointChanged)
				return false;
		}
		if (!PassesDiversity(contact, index))
			return false;
		if (record != NULL) {
			const bool replaceSet = !entry.hasSignedIdentity
				|| record->epoch > entry.signedEpoch
				|| entry.endpointSet.endpoints.empty();
			if (replaceSet) {
				entry.endpointSet = *record;
				entry.candidates.clear();
				entry.verified = false;
				entry.contact.endpoint = contact.endpoint;
				entry.candidates.reserve(record->endpoints.size());
				for (const kad6::K6Endpoint& endpoint : record->endpoints) {
					Entry::Candidate candidate;
					candidate.endpoint = endpoint;
					entry.candidates.push_back(candidate);
				}
			}
			entry.hasSignedIdentity = true;
			entry.nodePub = record->node_pub;
			entry.signedEpoch = record->epoch;
			entry.routerSignature = record->signature;
		}
		entry.contact.node_id = contact.node_id;
		entry.contact.caps = contact.caps;
		entry.contact.epoch = contact.epoch;
		Entry::Candidate* candidate = FindCandidate(entry, contact.endpoint);
		if (candidate == NULL)
			return false;
		candidate->lastSeen = nowSeconds;
		if (verified) {
			candidate->verified = true;
			candidate->failures = 0;
		}
		if (!entry.verified)
			entry.contact.endpoint = contact.endpoint;
		entry.lastSeen = nowSeconds;
		SelectBestVerifiedCandidate(entry);
		return true;
	}

	const std::size_t bucket = BucketFor(contact.node_id);
	if (bucket == KAD6_NO_INDEX)
		return false;
	std::size_t bucketCount = 0;
	std::size_t bucketVictim = KAD6_NO_INDEX;
	for (std::size_t i = 0; i < m_entries.size(); ++i) {
		if (BucketFor(m_entries[i].contact.node_id) != bucket)
			continue;
		++bucketCount;
		if (!m_entries[i].verified && (bucketVictim == KAD6_NO_INDEX
			|| m_entries[i].lastSeen < m_entries[bucketVictim].lastSeen))
			bucketVictim = i;
	}
	if (bucketCount >= KAD6_BUCKET_SIZE && bucketVictim == KAD6_NO_INDEX)
		return false;
	if (!PassesDiversity(contact, bucketVictim))
		return false;
	if (bucketCount >= KAD6_BUCKET_SIZE)
		m_entries.erase(m_entries.begin() + bucketVictim);
	if (m_entries.size() >= kad6::kK6RouteMaxStoredContacts) {
		// Prefer evicting the stalest probation entry. If every entry has been
		// verified, retain the table rather than accepting an unsolicited node.
		std::vector<Entry>::iterator victim = m_entries.end();
		for (std::vector<Entry>::iterator it = m_entries.begin();
			it != m_entries.end(); ++it) {
			if (!it->verified && (victim == m_entries.end()
				|| it->lastSeen < victim->lastSeen))
				victim = it;
		}
		if (victim == m_entries.end())
			return false;
		m_entries.erase(victim);
	}

	Entry entry;
	entry.contact = contact;
	entry.lastSeen = nowSeconds;
	entry.verified = false;
	if (record != NULL) {
		entry.hasSignedIdentity = true;
		entry.nodePub = record->node_pub;
		entry.signedEpoch = record->epoch;
		entry.routerSignature = record->signature;
		entry.endpointSet = *record;
		for (const kad6::K6Endpoint& endpoint : record->endpoints) {
			Entry::Candidate candidate;
			candidate.endpoint = endpoint;
			if (SameEndpoint(endpoint, contact.endpoint)) {
				candidate.lastSeen = nowSeconds;
				candidate.verified = verified;
			}
			entry.candidates.push_back(candidate);
		}
		SelectBestVerifiedCandidate(entry);
	}
	m_entries.push_back(entry);
	return true;
}

bool CKad6RoutingTable::AddProbation(const kad6::K6RouteContact& contact,
	std::uint64_t nowSeconds)
{
	return AddOrUpdate(contact, nowSeconds, false, NULL);
}

bool CKad6RoutingTable::MarkVerified(const kad6::K6RouteContact& contact,
	const kad6::K6RouterRecord& record, std::uint64_t nowSeconds)
{
	return AddOrUpdate(contact, nowSeconds, true, &record);
}

bool CKad6RoutingTable::AddSignedProbation(
	const kad6::K6RouteContact& contact,
	const kad6::K6RouterRecord& record, std::uint64_t nowSeconds)
{
	return AddOrUpdate(contact, nowSeconds, false, &record);
}

bool CKad6RoutingTable::IsVerified(const kad6::KadId& nodeId,
	const kad6::Kad6Address& address, std::uint16_t port) const
{
	const std::size_t index = FindById(nodeId);
	if (index == KAD6_NO_INDEX || !m_entries[index].hasSignedIdentity)
		return false;
	for (const Entry::Candidate& candidate : m_entries[index].candidates)
		if (candidate.verified && candidate.endpoint.addr == address
			&& candidate.endpoint.udp_port == port)
			return true;
	return false;
}

bool CKad6RoutingTable::LookupVerifiedIdentity(const kad6::Byte nodePub[32],
	kad6::Kad6Address& address, kad6::K6AsnInfo& asn) const
{
	address = kad6::Kad6Address();
	asn = kad6::K6AsnInfo();
	if (nodePub == NULL)
		return false;
	for (const Entry& entry : m_entries) {
		if (!entry.verified || !entry.hasSignedIdentity
			|| !kad6::Kad6CtEqual(entry.nodePub.data(), nodePub,
				entry.nodePub.size()))
			continue;
		if (!IsPublicAddress(entry.contact.endpoint.addr)
			|| !m_asnDatabase.Lookup(entry.contact.endpoint.addr, asn)
			|| asn.asn == 0)
			return false;
		address = entry.contact.endpoint.addr;
		return true;
	}
	return false;
}

bool CKad6RoutingTable::LookupAddressAsn(const kad6::Kad6Address& address,
		kad6::K6AsnInfo& asn) const
{
	asn = kad6::K6AsnInfo();
	return m_asnDatabase.Lookup(address, asn) && asn.asn != 0;
}

bool CKad6RoutingTable::ApplyPathEvidence(const kad6::Byte nodePub[32],
	std::uint64_t nowSeconds, kad6::K6PathCandidate& candidate) const
{
	return kad6::ApplyK6PathEvidence(m_pathEvidence, nodePub, nowSeconds, candidate);
}

void CKad6RoutingTable::NoteFailure(const kad6::KadId& nodeId)
{
	const std::size_t index = FindById(nodeId);
	if (index == KAD6_NO_INDEX)
		return;
	NoteFailure(nodeId, m_entries[index].contact.endpoint.addr,
		m_entries[index].contact.endpoint.udp_port);
}

void CKad6RoutingTable::NoteFailure(const kad6::KadId& nodeId,
	const kad6::Kad6Address& address, std::uint16_t port)
{
	const std::size_t index = FindById(nodeId);
	if (index == KAD6_NO_INDEX)
		return;
	Entry& entry = m_entries[index];
	for (Entry::Candidate& candidate : entry.candidates) {
		if (candidate.endpoint.addr != address || candidate.endpoint.udp_port != port)
			continue;
		if (candidate.failures < 255)
			++candidate.failures;
		if (candidate.failures >= 3)
			candidate.verified = false;
		SelectBestVerifiedCandidate(entry);
		return;
	}
	if (entry.failures < 255) ++entry.failures;
	if (entry.failures >= 3 && !entry.hasSignedIdentity)
		m_entries.erase(m_entries.begin() + index);
}

std::vector<kad6::K6RouteContact> CKad6RoutingTable::Closest(
	const kad6::KadId& target, std::size_t maximum, bool verifiedOnly) const
{
	struct Candidate {
		const Entry* entry;
		kad6::KadId distance;
	};
	std::vector<Candidate> candidates;
	for (const Entry& entry : m_entries) {
		if (verifiedOnly && !entry.verified)
			continue;
		Candidate candidate = {&entry, {}};
		for (std::size_t i = 0; i < target.size(); ++i)
			candidate.distance[i] = target[i] ^ entry.contact.node_id[i];
		candidates.push_back(candidate);
	}
	std::sort(candidates.begin(), candidates.end(),
		[](const Candidate& a, const Candidate& b) {
			return a.distance < b.distance;
		});
	maximum = maximum < candidates.size() ? maximum : candidates.size();
	std::vector<kad6::K6RouteContact> result;
	result.reserve(maximum);
	for (std::size_t i = 0; i < maximum; ++i)
		result.push_back(candidates[i].entry->contact);
	return result;
}

bool CKad6RoutingTable::BuildEndpointRace(const kad6::KadId& nodeId,
	std::uint64_t nowSeconds,
	std::vector<kad6::K6EndpointAttempt>& attempts) const
{
	attempts.clear();
	const std::size_t index = FindById(nodeId);
	if (index == KAD6_NO_INDEX)
		return false;
	const Entry& entry = m_entries[index];
	std::vector<kad6::K6EndpointCandidateHealth> health;
	health.reserve(entry.candidates.size());
	for (const Entry::Candidate& candidate : entry.candidates) {
		kad6::K6EndpointCandidateHealth state;
		state.endpoint = candidate.endpoint;
		state.verified = candidate.verified;
		state.consecutive_failures = candidate.failures;
		state.last_success = candidate.lastSeen;
		health.push_back(state);
	}
	return !entry.endpointSet.endpoints.empty()
		&& kad6::BuildK6EndpointRace(entry.endpointSet, health, nowSeconds,
			kad6::kK6HappyEyeballsDefaultDelayMs, attempts)
			== kad6::Kad6Status::Ok;
}

bool CKad6RoutingTable::NextProbation(Entry& out) const
{
	const Entry* oldest = NULL;
	const Entry::Candidate* oldestCandidate = NULL;
	for (const Entry& entry : m_entries) {
		if (entry.hasSignedIdentity) {
			for (const Entry::Candidate& candidate : entry.candidates)
				if (!candidate.verified && (oldestCandidate == NULL
					|| candidate.lastSeen < oldestCandidate->lastSeen)) {
					oldest = &entry;
					oldestCandidate = &candidate;
				}
		} else if (!entry.verified && oldestCandidate == NULL &&
			(oldest == NULL || entry.lastSeen < oldest->lastSeen))
			oldest = &entry;
	}
	if (oldest == NULL)
		return false;
	out = *oldest;
	if (oldestCandidate != NULL)
		out.contact.endpoint = oldestCandidate->endpoint;
	return true;
}

void CKad6RoutingTable::Expire(std::uint64_t nowSeconds)
{
	for (std::vector<Entry>::iterator entry = m_entries.begin();
		entry != m_entries.end(); ) {
		if (entry->hasSignedIdentity) {
			for (std::vector<Entry::Candidate>::iterator candidate =
				entry->candidates.begin(); candidate != entry->candidates.end(); ) {
				const std::uint64_t ttl = candidate->verified
					? KAD6_VERIFIED_TTL : KAD6_PROBATION_TTL;
				if (candidate->endpoint.valid_until <= nowSeconds
					|| nowSeconds < candidate->lastSeen
					|| (candidate->lastSeen != 0
						&& nowSeconds - candidate->lastSeen > ttl))
					candidate = entry->candidates.erase(candidate);
				else
					++candidate;
			}
			// A v2 nodes_v6.dat snapshot pins the signed identity, signature and
			// selected endpoint, but deliberately does not persist the complete
			// EndpointSet transcript.  Load() therefore leaves endpointSet empty
			// until the mandatory HELLO reconstructs and verifies it.  Candidate
			// expiry remains authoritative during that probation window.
			if (entry->candidates.empty()
				|| (entry->endpointSet.valid_until != 0
					&& entry->endpointSet.valid_until <= nowSeconds)) {
				entry = m_entries.erase(entry);
				continue;
			}
			SelectBestVerifiedCandidate(*entry);
			++entry;
			continue;
		}
		const std::uint64_t ttl = entry->verified
			? KAD6_VERIFIED_TTL : KAD6_PROBATION_TTL;
		if (nowSeconds < entry->lastSeen || nowSeconds - entry->lastSeen > ttl)
			entry = m_entries.erase(entry);
		else
			++entry;
	}
}

std::size_t CKad6RoutingTable::VerifiedSize() const
{
	std::size_t count = 0;
	for (const Entry& entry : m_entries)
		if (entry.verified && entry.hasSignedIdentity)
			++count;
	return count;
}

bool CKad6RoutingTable::LoadAsnDatabase()
{
	std::vector<kad6::Byte> bytes;
	const std::size_t maximum = kad6::kK6AsnSnapshotHeaderSize
		+ kad6::kK6AsnMaxEntries * kad6::kK6AsnSnapshotEntrySize;
	if (!ReadBoundedFile(AsnPath(), maximum, bytes))
		return false;
	std::uint64_t sequence = 0;
	std::vector<kad6::K6AsnPrefix> entries;
	const kad6::Kad6Status decoded = kad6::DecodeK6AsnSnapshot(
		bytes.data(), bytes.size(), sequence, entries);
	if (decoded != kad6::Kad6Status::Ok
		|| (m_asnDatabase.sequence() != 0
			&& sequence <= m_asnDatabase.sequence())
		|| m_asnDatabase.LoadEntries(sequence, entries) != kad6::Kad6Status::Ok) {
		AddDebugLogLine(false, _T("Kad6: rejected kad6_asn.dat (status=%hs, sequence=%I64u)"),
			kad6::Kad6StatusName(decoded), sequence);
		return false;
	}
	AddDebugLogLine(false, _T("Kad6: loaded offline ASN DB sequence=%I64u entries=%u"),
		sequence, static_cast<unsigned>(entries.size()));
	return true;
}

bool CKad6RoutingTable::LoadPathEvidence()
{
	std::vector<kad6::Byte> bytes;
	if (!ReadBoundedFile(PathEvidencePath(), 32u * 1024u * 1024u, bytes))
		return false;
	kad6::K6PathEvidenceSnapshot decoded;
	const kad6::Kad6Status status = kad6::DecodeK6PathEvidenceSnapshot(
		bytes.data(), bytes.size(), decoded);
	const std::uint64_t nowSeconds = static_cast<std::uint64_t>(time(NULL));
	if (status != kad6::Kad6Status::Ok
		|| decoded.generated_at > nowSeconds || decoded.valid_until <= nowSeconds
		|| (m_pathEvidence.sequence != 0
			&& decoded.sequence <= m_pathEvidence.sequence)) {
		AddDebugLogLine(false,
			_T("Kad6: rejected kad6_path_evidence.dat (status=%hs, sequence=%I64u)"),
			kad6::Kad6StatusName(status), decoded.sequence);
		return false;
	}
	m_pathEvidence = std::move(decoded);
	AddDebugLogLine(false,
		_T("Kad6: loaded offline AS/IXP path evidence sequence=%I64u records=%u"),
		m_pathEvidence.sequence,
		static_cast<unsigned>(m_pathEvidence.records.size()));
	return true;
}

bool CKad6RoutingTable::LoadPrivateBootstrap()
{
	const DWORD sequenceAttributes = GetFileAttributes(BootstrapSequencePath());
	if (sequenceAttributes != INVALID_FILE_ATTRIBUTES
		&& !LoadBootstrapSequence(m_bootstrapSequence)) {
		AddDebugLogLine(false, _T("Kad6: private bootstrap disabled: invalid anti-rollback state"));
		return false;
	}

	std::vector<kad6::Byte> pinBytes;
	std::vector<kad6::Byte> bundleBytes;
	if (!ReadBoundedFile(BootstrapPubPath(), kad6::kEd25519PubSize, pinBytes)
		|| pinBytes.size() != kad6::kEd25519PubSize
		|| !ReadBoundedFile(BootstrapPath(), kad6::kK6BootstrapMaxWireSize,
			bundleBytes))
		return false; // optional: no private bundle installed

	kad6::Ed25519Pub pinnedKey{};
	std::memcpy(pinnedKey.data(), pinBytes.data(), pinnedKey.size());
	kad6::K6BootstrapBundle bundle;
	const std::uint64_t now = static_cast<std::uint64_t>(time(NULL));
	const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
	const kad6::Kad6Status status = kad6::VerifyAndDecodeK6BootstrapBundle(
		crypto, pinnedKey, bundleBytes.data(),
		bundleBytes.size(), m_bootstrapSequence, now, bundle);
	if (status != kad6::Kad6Status::Ok) {
		// A previously consumed bundle is normal on resume; every other error is
		// logged because PRIVATE must never silently fall back to an untrusted file.
		if (status != kad6::Kad6Status::StaleEpoch)
			AddDebugLogLine(false, _T("Kad6: private bootstrap bundle rejected (%hs)"),
				kad6::Kad6StatusName(status));
		return false;
	}

	std::set<std::uint32_t> distinctAsns;
	std::set<std::uint32_t> distinctOperators;
	struct Candidate {
		kad6::K6RouteContact contact;
		const kad6::K6RouterRecord* record;
	};
	std::vector<Candidate> candidates;
	candidates.reserve(bundle.records.size());
	for (const kad6::K6RouterRecord& record : bundle.records) {
		const kad6::K6Endpoint* selected = NULL;
		for (const kad6::K6Endpoint& endpoint : record.endpoints) {
			if (IsPublicV6(endpoint.addr)
				&& endpoint.udp_port != 0
				&& (endpoint.transport_flags & kad6::kK6EpUdpKad6) != 0) {
				selected = &endpoint;
				break;
			}
		}
		if (selected == NULL) {
			AddDebugLogLine(false, _T("Kad6: private bootstrap contains a router without public IPv6"));
			return false;
		}
		kad6::K6AsnInfo asn;
		if (m_asnDatabase.Lookup(selected->addr, asn)) {
			distinctAsns.insert(asn.asn);
			if (asn.operator_group != 0)
				distinctOperators.insert(asn.operator_group);
		}
		Candidate candidate;
		candidate.contact.node_id = record.kad_id;
		candidate.contact.endpoint = *selected;
		candidate.contact.caps = record.caps;
		candidate.contact.epoch = record.epoch;
		candidate.record = &record;
		candidates.push_back(candidate);
	}
	if (distinctAsns.size() < 8 || distinctOperators.size() < 3) {
		AddDebugLogLine(false, _T("Kad6: private bootstrap rejected: diversity ASNs=%u/8 operators=%u/3"),
			static_cast<unsigned>(distinctAsns.size()),
			static_cast<unsigned>(distinctOperators.size()));
		return false;
	}

	// The distribution file is not allowed to choose our first contacts by
	// ordering them.  Shuffle once with the host CSPRNG; the paced probation
	// scheduler then probes this randomized order instead of walking the bundle.
	for (std::size_t remaining = candidates.size(); remaining > 1; --remaining) {
		std::uint64_t randomValue = 0;
		const std::uint64_t bound = static_cast<std::uint64_t>(remaining);
		const std::uint64_t limit = (std::numeric_limits<std::uint64_t>::max)()
			- ((std::numeric_limits<std::uint64_t>::max)() % bound);
		do {
			if (!crypto.random_bytes
				|| !crypto.random_bytes(reinterpret_cast<kad6::Byte*>(&randomValue),
					sizeof randomValue)) {
				AddDebugLogLine(false, _T("Kad6: private bootstrap disabled: CSPRNG failure"));
				return false;
			}
		} while (randomValue >= limit);
		const std::size_t selected = static_cast<std::size_t>(randomValue % bound);
		std::swap(candidates[remaining - 1], candidates[selected]);
	}

	const std::vector<Entry> previous = m_entries;
	std::size_t accepted = 0;
	for (const Candidate& candidate : candidates)
		if (AddSignedProbation(candidate.contact, *candidate.record, now))
			++accepted;
	if (accepted == 0 || !SaveBootstrapSequence(bundle.sequence)) {
		m_entries = previous;
		AddDebugLogLine(false, _T("Kad6: private bootstrap commit failed"));
		return false;
	}
	m_bootstrapSequence = bundle.sequence;
	if (!Save()) {
		m_entries = previous;
		AddDebugLogLine(false, _T("Kad6: private bootstrap nodes_v6.dat commit failed"));
		return false;
	}
	AddDebugLogLine(false, _T("Kad6: private bootstrap accepted sequence=%I64u candidates=%u probation=%u ASNs=%u operators=%u"),
		bundle.sequence, static_cast<unsigned>(bundle.records.size()),
		static_cast<unsigned>(accepted), static_cast<unsigned>(distinctAsns.size()),
		static_cast<unsigned>(distinctOperators.size()));
	return true;
}

bool CKad6RoutingTable::Load()
{
	m_entries.clear();
	CFile file;
	try {
		if (!file.Open(SnapshotPath(), CFile::modeRead | CFile::shareDenyWrite))
			return false;
		const ULONGLONG length64 = file.GetLength();
		const ULONGLONG maximum = kad6::kK6RouteSnapshotHeaderV1Size
			+ kad6::kK6RouteMaxStoredContacts * kad6::kK6RouteSnapshotEntryV2Size;
		if (length64 > maximum) {
			file.Close();
			return false;
		}
		std::vector<kad6::Byte> bytes(static_cast<std::size_t>(length64));
		if (!bytes.empty() && file.Read(bytes.data(), static_cast<UINT>(bytes.size()))
			!= bytes.size()) {
			file.Close();
			return false;
		}
		file.Close();

		std::vector<kad6::K6RouteSnapshotEntry> decoded;
		const kad6::Kad6Status status = kad6::DecodeK6RouteSnapshot(
			bytes.empty() ? NULL : bytes.data(), bytes.size(), decoded);
		if (status != kad6::Kad6Status::Ok)
			return false;
		const std::uint64_t now = static_cast<std::uint64_t>(time(NULL));
		for (const kad6::K6RouteSnapshotEntry& stored : decoded) {
			// Never trust verification across restarts. Every persisted contact
			// must answer a new HELLO before it can be returned to another node.
			if (now == 0 || now < stored.last_seen
				|| now - stored.last_seen > KAD6_PROBATION_TTL
				|| (stored.contact.endpoint.valid_until != 0
					&& stored.contact.endpoint.valid_until <= now))
				continue;
			if (AddOrUpdate(stored.contact, stored.last_seen, false, NULL)) {
				const std::size_t index = FindById(stored.contact.node_id);
				if (index != KAD6_NO_INDEX) {
					Entry& entry = m_entries[index];
					entry.failures = stored.failures;
					entry.hasSignedIdentity = stored.has_signed_identity != 0;
					entry.nodePub = stored.node_pub;
					entry.signedEpoch = stored.signed_epoch;
					entry.routerSignature = stored.router_signature;
					Entry::Candidate candidate;
					candidate.endpoint = stored.contact.endpoint;
					candidate.lastSeen = stored.last_seen;
					candidate.failures = stored.failures;
					entry.candidates.push_back(candidate);
				}
			}
		}
		return true;
	}
	catch (CFileException* error) {
		error->Delete();
		return false;
	}
}

bool CKad6RoutingTable::Save() const
{
	std::vector<kad6::K6RouteSnapshotEntry> entries;
	entries.reserve(m_entries.size());
	for (const Entry& entry : m_entries) {
		kad6::K6RouteSnapshotEntry stored;
		stored.contact = entry.contact;
		stored.last_seen = entry.lastSeen;
		stored.verified = entry.verified ? 1 : 0;
		stored.failures = entry.failures;
		stored.has_signed_identity = entry.hasSignedIdentity ? 1 : 0;
		stored.node_pub = entry.nodePub;
		stored.signed_epoch = entry.signedEpoch;
		stored.router_signature = entry.routerSignature;
		entries.push_back(stored);
	}
	std::vector<kad6::Byte> bytes;
	if (kad6::EncodeK6RouteSnapshot(entries, bytes) != kad6::Kad6Status::Ok)
		return false;

	const CString path = SnapshotPath();
	const CString temporary = path + _T(".new");
	try {
		CFile file(temporary, CFile::modeCreate | CFile::modeWrite
			| CFile::shareExclusive);
		if (!bytes.empty())
			file.Write(bytes.data(), static_cast<UINT>(bytes.size()));
		file.Flush();
		file.Close();
		if (!MoveFileEx(temporary, path,
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
			DeleteFile(temporary);
			return false;
		}
		return true;
	}
	catch (CFileException* error) {
		error->Delete();
		DeleteFile(temporary);
		return false;
	}
}

} // namespace Kademlia
