// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_ed2k_policy.h"
#include "kad6/kad6_gateway.h"
#include "kad6/kad6_hints.h"
#include "kad6/kad6_vep.h"

namespace kad6_fuzz {

bool FuzzGateway(const Config& cfg, Report& report) {
    report.target="gateway";Rng rng(cfg.seed^0x4b362d3447415445ull);
    std::vector<std::vector<Byte>> corpus={{},{1},{0xe3,1,0,0,0,1},{0xc5,5,0,0,0,0x98,1,2,3,4}};
    for(std::size_t i=0;i<cfg.iterations;++i){
        std::vector<Byte>in=Mutate(corpus,rng,i,kad6::kK6StreamMaxFrameData+64);report.max_input=(std::max)(report.max_input,in.size());
        const Byte*p=DataOrNull(in);std::size_t used=0;kad6::K6TargetTicketRequest tr;kad6::K6TargetTicketResponse tp;kad6::K6Dial d;kad6::K6DialResult dr;kad6::K6StreamData sd;kad6::K6StreamHalfClose hc;kad6::K6StreamClose sc;kad6::K6SourceHints hints;kad6::K6VirtualIdentityEndpoint vep;kad6::K6ParsedPex pex;kad6::K6Ed2kFrameView frame;
        const kad6::Kad6Status statuses[]={
            kad6::DecodeK6TargetTicketRequest(p,in.size(),tr,&used),kad6::DecodeK6TargetTicketResponse(p,in.size(),tp,&used),
            kad6::DecodeK6Dial(p,in.size(),d,&used),kad6::DecodeK6DialResult(p,in.size(),dr,&used),
            kad6::DecodeK6StreamData(p,in.size(),sd,&used),kad6::DecodeK6StreamHalfClose(p,in.size(),hc,&used),
            kad6::DecodeK6StreamClose(p,in.size(),sc,&used),kad6::DecodeK6SourceHints(p,in.size(),hints,&used),
            kad6::DecodeK6Vep(p,in.size(),vep,&used),kad6::DecodeEd2kSourceExchange(kad6::kEd2kOpAnswerSources,p,in.size(),pex),
            kad6::DecodeEd2kSourceExchange(kad6::kEd2kOpAnswerSources2,p,in.size(),pex),kad6::DecodeK6Ed2kFrame(p,in.size(),frame)};
        for(auto s:statuses)Require(report,static_cast<int>(s)>=0,"decoder returned valid status");
        if(kad6::DecodeK6StreamData(p,in.size(),sd,&used)==kad6::Kad6Status::Ok){std::vector<Byte>w;Require(report,kad6::EncodeK6StreamData(sd,w)==kad6::Kad6Status::Ok,"stream success re-encodes");report.max_output=(std::max)(report.max_output,w.size());}
        ++report.iterations;
    }return report.failures==0;
}

} // namespace kad6_fuzz
