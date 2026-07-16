#include "kad6/kad6_path.h"

#include <cstring>
#include <iostream>
#include <vector>

using namespace kad6;

static int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { std::cerr << "FAIL line " << __LINE__ << ": " #x "\n"; return 1; } } while (0)

struct RandomStream { std::vector<std::uint64_t> values; std::size_t next = 0; };
static bool Random(void* context, Byte* out, std::size_t length)
{
    if (!context || length != 8) return false;
    RandomStream& stream = *static_cast<RandomStream*>(context);
    if (stream.next >= stream.values.size()) return false;
    const std::uint64_t value = stream.values[stream.next++];
    for (unsigned i = 0; i < 8; ++i) out[i] = static_cast<Byte>(value >> (i * 8));
    return true;
}

static K6PathCandidate Candidate(Byte id, Byte prefix, std::uint32_t asn,
                                 std::uint32_t op, bool exit = true)
{
    K6PathCandidate c;
    c.node_pub.fill(id); c.user_hash.fill(static_cast<Byte>(id + 64));
    c.address.family = Kad6Address::Family::IPv6;
    c.address.addr[0] = 0x20; c.address.addr[1] = 0x01;
    c.address.addr[2] = 0x0d; c.address.addr[3] = 0xb8;
    c.address.addr[4] = prefix; c.address.addr[5] = 0;
    c.address.addr[6] = id;
    c.asn = asn; c.operator_group = op; c.weight = id;
    c.authenticated = c.endpoint_verified = c.connected = true;
    c.supports_strict3 = c.supports_shaping = c.has_capacity = true;
    c.supports_exit = exit;
    return c;
}

int main()
{
    std::vector<K6PathCandidate> cands{
        Candidate(1, 1, 64501, 1), Candidate(2, 2, 64502, 2),
        Candidate(3, 3, 64503, 3), Candidate(4, 4, 64504, 4)};
    K6StrictPath path;
    RandomStream random{{0, 0, 0}};
    CHECK(SelectK6StrictPath(cands, nullptr, Random, &random, path) == K6PathStatus::Ok);
    CHECK(path.index[0] != path.index[1]);
    CHECK(path.index[0] != path.index[2]);
    CHECK(path.index[1] != path.index[2]);
    CHECK(!Kad6AddressInSameSubnet(cands[path.index[0]].address, cands[path.index[1]].address, 48));

    // A hard guard pin is honored even when weighted randomness would choose another.
    random = RandomStream{{999, 0, 0}};
    CHECK(SelectK6StrictPath(cands, cands[2].node_pub.data(), Random, &random, path) == K6PathStatus::Ok);
    CHECK(path.index[0] == 2);

    std::array<Byte, 32> absent{}; absent.fill(99);
    random = RandomStream{{0}};
    CHECK(SelectK6StrictPath(cands, absent.data(), Random, &random, path) == K6PathStatus::PinnedGuardUnavailable);

    // Same /48, ASN or known operator group each blocks a strict path.
    std::vector<K6PathCandidate> same48{
        Candidate(1, 7, 64501, 1), Candidate(2, 7, 64502, 2), Candidate(3, 7, 64503, 3)};
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(same48, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);
    std::vector<K6PathCandidate> sameAsn{
        Candidate(1, 1, 64501, 1), Candidate(2, 2, 64501, 2), Candidate(3, 3, 64501, 3)};
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(sameAsn, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);
    std::vector<K6PathCandidate> sameOp{
        Candidate(1, 1, 64501, 9), Candidate(2, 2, 64502, 9), Candidate(3, 3, 64503, 9)};
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(sameOp, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);

    // Co-seeders and candidates without verified metadata/capacity are excluded.
    cands[0].current_content_peer = true;
    cands[1].endpoint_verified = false;
    cands[2].has_capacity = false;
    random = RandomStream{{0}};
    CHECK(SelectK6StrictPath(cands, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);

    // CSPRNG failure is explicit, never replaced by deterministic first-entry selection.
    std::vector<K6PathCandidate> valid{
        Candidate(1, 1, 64501, 1), Candidate(2, 2, 64502, 2), Candidate(3, 3, 64503, 3)};
    RandomStream empty;
    CHECK(SelectK6StrictPath(valid, nullptr, Random, &empty, path) == K6PathStatus::RandomFailed);

    // Class-5 shaping is part of STRICT, not an optional post-selection
    // downgrade. A hop lacking it is ineligible.
    valid[0].supports_shaping = false;
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(valid, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);
    valid[0].supports_shaping = true;

    // NodeIdentity and UserHash are both uniqueness boundaries.
    valid[1].node_pub = valid[0].node_pub;
    random = RandomStream{{0, 0, 0}};
    CHECK(SelectK6StrictPath(valid, nullptr, Random, &random, path) == K6PathStatus::NotDiverse);

    // L5/Q24: f^2 is not used for network observers.  Forward/reverse AS and
    // IXP unions are checked explicitly and missing evidence fails closed.
    std::vector<K6PathCandidate> network{
        Candidate(1, 1, 64501, 1), Candidate(2, 2, 64502, 2),
        Candidate(3, 3, 64503, 3), Candidate(4, 4, 64504, 4)};
    network[0].access_forward_as={100,200};network[0].access_reverse_as={100,201};
    network[0].access_forward_ixp={10};network[0].access_reverse_ixp={11};
    network[0].access_multi_vantage=true;
    network[2].egress_forward_as={300,200};network[2].egress_reverse_as={301};
    network[2].egress_forward_ixp={12};network[2].egress_reverse_ixp={13};
    network[2].egress_multi_vantage=true;
    network[3].egress_forward_as={400};network[3].egress_reverse_as={401};
    network[3].egress_forward_ixp={14};network[3].egress_reverse_ixp={15};
    network[3].egress_multi_vantage=true;
    K6NetworkPathPolicy policy;
    CHECK(CheckK6NetworkPathDiversity(network[0],network[2],policy)==
          K6PathStatus::NetworkObserverOverlap);
    CHECK(CheckK6NetworkPathDiversity(network[0],network[3],policy)==K6PathStatus::Ok);
    random=RandomStream{{0,0,0}};
    CHECK(SelectK6StrictPathV2(network,network[0].node_pub.data(),policy,Random,&random,path)==
          K6PathStatus::Ok&&path.index[2]==3);
    network[3].egress_multi_vantage=false;random=RandomStream{{0,0,0}};
    CHECK(SelectK6StrictPathV2(network,network[0].node_pub.data(),policy,Random,&random,path)==
          K6PathStatus::NetworkObserverOverlap);
    std::vector<K6PathTraceSample> traces(100);
    for(std::size_t i=0;i<traces.size();++i){traces[i].baseline_overlap=i<40;
        traces[i].selected_overlap=i<8;}
    const K6PathTraceReport report=EvaluateK6PathTraces(traces);
    CHECK(report.samples==100&&report.baseline_overlaps==40&&report.selected_overlaps==8);
    CHECK(report.selected_probability<report.baseline_probability);

    // Public IPv4 is a verified transport for the same logical Kad6 plane.
    // IPv4 diversity uses /20 while ASN and operator boundaries remain common.
    std::vector<K6PathCandidate> v4{
        Candidate(10,1,64610,10),Candidate(11,2,64611,11),Candidate(12,3,64612,12)};
    for(std::size_t i=0;i<v4.size();++i){v4[i].address.family=Kad6Address::Family::IPv4;
        v4[i].address.addr={static_cast<Byte>(20+i*16),1,2,static_cast<Byte>(10+i)};}
    random=RandomStream{{0,0,0}};
    CHECK(SelectK6StrictPath(v4,nullptr,Random,&random,path)==K6PathStatus::Ok);
    v4[1].address.addr={20,1,15,99};random=RandomStream{{0,0,0}};
    CHECK(SelectK6StrictPath(v4,nullptr,Random,&random,path)==K6PathStatus::NotDiverse);

    // The bounded offline evidence snapshot is canonical, exact-length and
    // keyed by NodeIdentity. Expired evidence can never enable STRICT.
    K6PathEvidenceSnapshot evidence;evidence.sequence=7;evidence.generated_at=1000;
    evidence.valid_until=2000;evidence.dataset_hash.fill(0x44);
    K6PathEvidenceRecord er;er.node_pub.fill(0x22);er.access_forward_as={100,200};
    er.access_reverse_as={101,201};er.access_forward_ixp={10};er.access_reverse_ixp={11};
    er.egress_forward_as={300};er.egress_reverse_as={301};
    er.egress_forward_ixp={12};er.egress_reverse_ixp={13};
    er.access_multi_vantage=er.egress_multi_vantage=true;evidence.records.push_back(er);
    std::vector<Byte> evidenceWire;
    CHECK(EncodeK6PathEvidenceSnapshot(evidence,evidenceWire)==Kad6Status::Ok);
    K6PathEvidenceSnapshot evidenceDecoded;
    CHECK(DecodeK6PathEvidenceSnapshot(evidenceWire.data(),evidenceWire.size(),evidenceDecoded)==
          Kad6Status::Ok&&evidenceDecoded.sequence==7&&evidenceDecoded.records.size()==1);
    K6PathCandidate evidenced=Candidate(20,20,64700,20);evidenced.node_pub.fill(0x22);
    CHECK(ApplyK6PathEvidence(evidenceDecoded,evidenced.node_pub.data(),1500,evidenced)&&
          evidenced.access_forward_as.size()==2&&evidenced.egress_reverse_ixp[0]==13);
    CHECK(!ApplyK6PathEvidence(evidenceDecoded,evidenced.node_pub.data(),2000,evidenced));
    evidenceWire.push_back(0);
    CHECK(DecodeK6PathEvidenceSnapshot(evidenceWire.data(),evidenceWire.size(),evidenceDecoded)==
          Kad6Status::Malformed);

    // Unknown inferred edges contribute only to the conservative upper bound.
    traces.assign(100,K6PathTraceSample{});
    for(std::size_t i=0;i<traces.size();++i){traces[i].baseline_overlap=i<30;
        traces[i].baseline_unknown=i>=30&&i<50;traces[i].selected_overlap=i<5;
        traces[i].selected_unknown=i>=5&&i<10;}
    std::vector<Byte> traceWire;
    CHECK(EncodeK6PathTraceFile(traces,traceWire)==Kad6Status::Ok);
    std::vector<K6PathTraceSample> traceDecoded;
    CHECK(DecodeK6PathTraceFile(traceWire.data(),traceWire.size(),traceDecoded)==
          Kad6Status::Ok&&traceDecoded.size()==100);
    const K6PathTraceReport bounded=EvaluateK6PathTraces(traceDecoded);
    CHECK(bounded.baseline_probability==0.30&&bounded.baseline_upper_probability==0.50&&
          bounded.selected_probability==0.05&&bounded.selected_upper_probability==0.10);
    traceWire.push_back(0);
    CHECK(DecodeK6PathTraceFile(traceWire.data(),traceWire.size(),traceDecoded)==
          Kad6Status::Malformed);

    std::cout << "kad6 strict path tests: " << checks << " checks, PASS\n";
    return 0;
}
