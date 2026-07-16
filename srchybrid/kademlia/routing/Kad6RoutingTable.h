// Native IPv6 Kademlia routing table (K6-2).
// Kept separate from CRoutingZone because that class and its anti-Sybil maps
// are fundamentally keyed by uint32 IPv4 addresses.
#pragma once

#include "kad6/kad6_routing.h"
#include "kad6/kad6_asn.h"
#include "kad6/kad6_bootstrap.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Kademlia
{
	class CKad6RoutingTable
	{
	public:
		struct Entry
		{
			kad6::K6RouteContact contact;
			std::uint64_t lastSeen = 0;
			bool verified = false;
			kad6::Byte failures = 0;
			bool hasSignedIdentity = false;
			kad6::Ed25519Pub nodePub{};
			std::uint64_t signedEpoch = 0;
			kad6::Ed25519Sig routerSignature{};
		};

		CKad6RoutingTable();
		~CKad6RoutingTable();

		// Contacts learned indirectly remain in probation. A contact is promoted
		// only after a transaction-bound response arrives from its exact endpoint.
		bool AddProbation(const kad6::K6RouteContact& contact,
			std::uint64_t nowSeconds);
		bool MarkVerified(const kad6::K6RouteContact& contact,
			const kad6::K6RouterRecord& record,
			std::uint64_t nowSeconds);
		bool AddSignedProbation(const kad6::K6RouteContact& contact,
			const kad6::K6RouterRecord& record,
			std::uint64_t nowSeconds);
		bool IsVerified(const kad6::KadId& nodeId,
			const kad6::Kad6Address& address, std::uint16_t port) const;
		// K6-6 path construction bridge.  A TCP tunnel candidate is eligible
		// for STRICT diversity only when its HELLO NodeIdentity also appears in
		// a verified, signed Kad6 routing entry and the offline ASN database can
		// classify its public IPv6 endpoint.
		bool LookupVerifiedIdentity(const kad6::Byte nodePub[32],
			kad6::Kad6Address& address, kad6::K6AsnInfo& asn) const;
		void NoteFailure(const kad6::KadId& nodeId);

		std::vector<kad6::K6RouteContact> Closest(
			const kad6::KadId& target, std::size_t maximum,
			bool verifiedOnly = true) const;
		bool NextProbation(Entry& out) const;
		void Expire(std::uint64_t nowSeconds);

		std::size_t Size() const { return m_entries.size(); }
		std::size_t VerifiedSize() const;
		bool Load();
		bool Save() const;
		bool LoadAsnDatabase();
		bool LoadPrivateBootstrap();
		bool HasAsnDatabase() const { return !m_asnDatabase.empty(); }
		std::size_t AsnEntryCount() const { return m_asnDatabase.entry_count(); }

	private:
		bool AddOrUpdate(const kad6::K6RouteContact& contact,
			std::uint64_t nowSeconds, bool verified,
			const kad6::K6RouterRecord* record);
		bool PassesDiversity(const kad6::K6RouteContact& contact,
			std::size_t ignoreIndex) const;
		std::size_t FindById(const kad6::KadId& nodeId) const;
		std::size_t BucketFor(const kad6::KadId& nodeId) const;

		std::vector<Entry> m_entries;
		kad6::KadId m_localId;
		kad6::K6AsnDatabase m_asnDatabase;
		std::uint64_t m_bootstrapSequence = 0;
	};
}
