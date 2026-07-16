// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_path.h"

namespace kad6_fuzz {

bool FuzzPath(const Config& config, Report& report) {
    kad6::K6PathEvidenceSnapshot snapshot;
    snapshot.sequence=1;snapshot.generated_at=100;snapshot.valid_until=200;
    snapshot.dataset_hash.fill(0x55);
    kad6::K6PathEvidenceRecord record;record.node_pub.fill(0x33);
    record.access_forward_as={100};record.access_reverse_as={101};
    record.egress_forward_as={200};record.egress_reverse_as={201};
    record.access_multi_vantage=record.egress_multi_vantage=true;
    snapshot.records.push_back(record);
    std::vector<Byte> evidence;
    (void)kad6::EncodeK6PathEvidenceSnapshot(snapshot,evidence);
    std::vector<kad6::K6PathTraceSample> samples(2);
    samples[0].baseline_overlap=true;samples[0].selected_unknown=true;
    std::vector<Byte> trace;
    (void)kad6::EncodeK6PathTraceFile(samples,trace);
    const std::vector<std::vector<Byte>> corpus={{},evidence,trace,
        {static_cast<Byte>('K'),static_cast<Byte>('6'),static_cast<Byte>('P'),static_cast<Byte>('E')},
        std::vector<Byte>(4096,0xff)};
    report.target="path";Rng rng(config.seed^0x4b3650415448ull);
    for(std::size_t i=0;i<config.iterations;++i){
        std::vector<Byte> input=Mutate(corpus,rng,i,65536);
        kad6::K6PathEvidenceSnapshot decodedEvidence;
        const kad6::Kad6Status evidenceStatus=kad6::DecodeK6PathEvidenceSnapshot(
            DataOrNull(input),input.size(),decodedEvidence);
        if(evidenceStatus==kad6::Kad6Status::Ok){
            Require(report,decodedEvidence.records.size()<=kad6::kK6PathEvidenceMaxRecords,
                "evidence record cap");
            std::vector<Byte> encoded;
            Require(report,kad6::EncodeK6PathEvidenceSnapshot(decodedEvidence,encoded)==
                kad6::Kad6Status::Ok&&encoded==input,"canonical evidence round trip");
            report.max_output=(std::max)(report.max_output,encoded.size());
        }
        std::vector<kad6::K6PathTraceSample> decodedTrace;
        const kad6::Kad6Status traceStatus=kad6::DecodeK6PathTraceFile(
            DataOrNull(input),input.size(),decodedTrace);
        if(traceStatus==kad6::Kad6Status::Ok){
            Require(report,decodedTrace.size()<=kad6::kK6PathTraceMaxSamples,
                "trace sample cap");
            std::vector<Byte> encoded;
            Require(report,kad6::EncodeK6PathTraceFile(decodedTrace,encoded)==
                kad6::Kad6Status::Ok&&encoded==input,"canonical trace round trip");
            report.max_output=(std::max)(report.max_output,encoded.size());
        }
        report.max_input=(std::max)(report.max_input,input.size());++report.iterations;
    }
    return report.failures==0;
}

} // namespace kad6_fuzz
