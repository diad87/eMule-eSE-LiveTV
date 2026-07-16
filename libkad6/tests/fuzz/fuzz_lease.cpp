// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_lease.h"

namespace kad6_fuzz {
static kad6::K6SourceBind Bind() {
    kad6::K6SourceBind b;
    for(Byte i=0;i<16;++i){b.file_hash[i]=i+1;b.compat_user_hash[i]=0x20+i;b.bind_nonce[i]=0x80+i;}
    for(Byte i=0;i<32;++i)b.compat_pub_fingerprint[i]=0x40+i;
    b.file_size=42;b.desired_family=4;b.transport_mask=kad6::kK6TransportTcp;
    b.flags=kad6::kK6SourceAllowInbound|kad6::kK6SourceFile;b.requested_lifetime_s=600;
    b.max_upload_bps=1000;b.source_epoch=1;b.requested_mode=kad6::K6BindingMode::DedicatedVep;
    b.compat_proof.assign(96,0x55);return b;
}
static std::vector<std::vector<Byte>> Corpus(){
    auto b=Bind();std::vector<Byte>bw;kad6::EncodeK6SourceBind(b,bw);
    kad6::K6SourceBound v;v.status=kad6::K6SourceBoundStatus::Ok;v.transport_mask=b.transport_mask;v.flags=b.flags;
    v.binding_mode=kad6::K6BindingMode::DedicatedVep;v.identity_mode=kad6::K6IdentityMode::OriginatorVep;v.endpoint_slot=1;
    v.source_lease_id=1;v.lifetime_s=600;v.refresh_after_s=300;v.virtual_endpoint.addr.family=kad6::Kad6Address::Family::IPv4;
    v.virtual_endpoint.addr.addr={8,8,8,8};v.virtual_endpoint.tcp_port=4662;v.exit_apparent_ip=v.virtual_endpoint.addr;
    v.bind_nonce=b.bind_nonce;for(Byte i=0;i<32;++i)v.exit_node_pub[i]=i+1;std::vector<Byte>vw;kad6::EncodeK6SourceBound(v,vw);
    kad6::K6SourceUnbind u;u.source_lease_id=1;u.source_epoch=2;u.bind_nonce=b.bind_nonce;std::vector<Byte>uw;kad6::EncodeK6SourceUnbind(u,uw);
    return {{},bw,vw,uw,{1,2,3},std::vector<Byte>(2048,0xff)};
}
bool FuzzLease(const Config& config,Report& report){report.target="lease";auto corpus=Corpus();Rng rng(config.seed^0x4c454153u);
    for(std::size_t i=0;i<config.iterations;++i){auto input=Mutate(corpus,rng,i,4096);const Byte*data=DataOrNull(input);std::size_t used=0;
        kad6::K6SourceBind b;kad6::K6SourceBound v;kad6::K6SourceUnbind u;
        auto sb=kad6::DecodeK6SourceBind(data,input.size(),b,&used);if(sb==kad6::Kad6Status::Ok){Require(report,used<=input.size(),"bind consumed");Require(report,b.compat_proof.size()<=kad6::kK6SourceBindMaxProof,"proof cap");}
        used=0;auto sv=kad6::DecodeK6SourceBound(data,input.size(),v,&used);if(sv==kad6::Kad6Status::Ok)Require(report,used<=input.size(),"bound consumed");
        used=0;auto su=kad6::DecodeK6SourceUnbind(data,input.size(),u,&used);if(su==kad6::Kad6Status::Ok)Require(report,used<=input.size(),"unbind consumed");
        report.max_input=(std::max)(report.max_input,input.size());report.max_output=(std::max)(report.max_output,b.compat_proof.size());}
    report.iterations=config.iterations;return report.failures==0;}
}
