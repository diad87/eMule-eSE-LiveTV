// SPDX-License-Identifier: MIT
#include "kad6/kad6_release.h"
#include <cstdio>
#include <cstring>
#include <vector>
using namespace kad6;
static int p=0,f=0;
#define CHECK(x,m) do{if(x)++p;else{++f;std::printf(" FAIL %s\n",m);}}while(0)
static void Digest(const Byte* m,std::size_t n,Byte out[32]){for(size_t i=0;i<32;++i)out[i]=(Byte)i;for(size_t i=0;i<n;++i)out[i%32]^=(Byte)(m[i]+i);}
static bool Sign(const Byte*,std::size_t,const Byte* m,std::size_t n,Byte s[64]){Digest(m,n,s);memcpy(s+32,s,32);return true;}
static bool Verify(const Byte*,const Byte* m,std::size_t n,const Byte s[64]){Byte x[64];Sign(nullptr,0,m,n,x);return Kad6CtEqual(x,s,64);}
int main(){Kad6CryptoHooks c;c.ed25519_sign=Sign;c.ed25519_verify=Verify;K6ReleaseEvidence e;e.gate_mask=0xffff;e.issued_at=4000000;e.valid_until=e.issued_at+86400;e.observed_to=e.issued_at;e.observed_from=e.observed_to-kK6ReleaseMinObservationSeconds;e.admission_attempts=100;e.admission_success_ppm=950000;e.useful_headroom_bps=3500;e.node_pub[0]=7;e.field_digest[0]=1;e.external_audit_digest[0]=2;std::vector<Byte>w;CHECK(SignK6ReleaseEvidence(c,e,w)==Kad6Status::Ok,"sign");CHECK(w.size()==kK6ReleaseEvidenceWireSize,"fixed wire");K6ReleaseEvidence d;CHECK(DecodeK6ReleaseEvidence(w.data(),w.size(),d)==Kad6Status::Ok,"decode");CHECK(EvaluateK6ReleaseEvidence(c,d,e.node_pub.data(),e.issued_at+1)==K6ReleaseGateStatus::Ok,"policy accepts complete evidence");for(size_t i=0;i<w.size();++i){K6ReleaseEvidence q;if(DecodeK6ReleaseEvidence(w.data(),i,q)==Kad6Status::Ok){++f;break;}}CHECK(true,"prefix sweep");d.gate_mask=0x7fff;CHECK(EvaluateK6ReleaseEvidence(c,d,e.node_pub.data(),e.issued_at+1)==K6ReleaseGateStatus::BadSignature,"mutation invalidates signature");e.gate_mask=0x7fff;CHECK(SignK6ReleaseEvidence(c,e,w)==Kad6Status::Ok,"resign incomplete");CHECK(EvaluateK6ReleaseEvidence(c,e,e.node_pub.data(),e.issued_at+1)==K6ReleaseGateStatus::GatesIncomplete,"all gates required");std::printf("test_kad6_release: %d passed, %d failed\n",p,f);return f?1:0;}
