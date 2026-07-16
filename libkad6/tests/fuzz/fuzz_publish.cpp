// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_publish.h"

namespace kad6_fuzz {
static std::vector<std::vector<Byte>> Corpus(){kad6::K6Publish p;p.record_kind=kad6::K6RecordKind::Source;p.network_mask=3;p.flags=kad6::kK6PublishFlagSigned;p.requested_ttl_s=600;p.record_epoch=1;p.target_hash[0]=1;p.source_id[0]=2;p.record={1,2,3};std::vector<Byte>pw;kad6::EncodeK6Publish(p,pw);
    kad6::K6PublishAck a;a.status=kad6::K6PublishStatus::Sent;a.published_networks=1;a.replica_count=1;a.effective_ttl_s=600;a.publish_lease_id=1;a.record_epoch=1;a.refresh_after_s=300;std::vector<Byte>aw;kad6::EncodeK6PublishAck(a,aw);
    kad6::K6Unpublish u;u.publish_lease_id=1;u.record_epoch=2;u.target_hash=p.target_hash;u.source_id=p.source_id;std::vector<Byte>uw;kad6::EncodeK6Unpublish(u,uw);
    return {{},pw,aw,uw,{1,2,3},std::vector<Byte>(70000,0xff)};}
bool FuzzPublish(const Config& config,Report& report){report.target="publish";auto corpus=Corpus();Rng rng(config.seed^0x5055424cu);
    for(std::size_t i=0;i<config.iterations;++i){auto input=Mutate(corpus,rng,i,70000);const Byte*data=DataOrNull(input);std::size_t used=0;kad6::K6Publish p;kad6::K6PublishAck a;kad6::K6Unpublish u;
        auto sp=kad6::DecodeK6Publish(data,input.size(),p,&used);if(sp==kad6::Kad6Status::Ok){Require(report,used<=input.size(),"publish consumed");Require(report,p.record.size()<=kad6::kK6PublishMaxRecordBytes,"record cap");}
        used=0;auto sa=kad6::DecodeK6PublishAck(data,input.size(),a,&used);if(sa==kad6::Kad6Status::Ok){Require(report,used<=input.size(),"ack consumed");Require(report,a.error_detail.size()<=kad6::kK6PublishMaxErrorBytes,"error cap");}
        used=0;auto su=kad6::DecodeK6Unpublish(data,input.size(),u,&used);if(su==kad6::Kad6Status::Ok)Require(report,used<=input.size(),"unpublish consumed");
        report.max_input=(std::max)(report.max_input,input.size());report.max_output=(std::max)(report.max_output,p.record.size()+a.error_detail.size());}
    report.iterations=config.iterations;return report.failures==0;}
}
