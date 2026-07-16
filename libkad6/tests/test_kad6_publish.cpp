// SPDX-License-Identifier: MIT
#include "kad6/kad6_publish.h"
#include <cstdio>
#include <cstring>
#include <vector>
using namespace kad6;
static int g_pass=0,g_fail=0;
#define CHECK(c,m) do{if(c)++g_pass;else{++g_fail;std::printf("  FAIL: %s (%s:%d)\n",m,__FILE__,__LINE__);}}while(0)

static bool Hash(const Byte* p,std::size_t n,Byte out[32]){std::uint64_t h=1469598103934665603ull;for(std::size_t i=0;i<n;++i){h^=p[i];h*=1099511628211ull;}for(int i=0;i<32;++i){h^=static_cast<std::uint64_t>(i)+0x9e3779b97f4a7c15ull;h*=1099511628211ull;out[i]=static_cast<Byte>(h>>(8*(i%8)));}return true;}
static bool Sign(const Byte* sk,std::size_t skn,const Byte* msg,std::size_t n,Byte sig[64]){if(!sk||skn!=32)return false;std::vector<Byte>v(sk,sk+skn);v.insert(v.end(),msg,msg+n);Hash(v.data(),v.size(),sig);v.push_back(0x5a);Hash(v.data(),v.size(),sig+32);return true;}
static bool Verify(const Byte pub[32],const Byte* msg,std::size_t n,const Byte sig[64]){Byte expected[64];return Sign(pub,32,msg,n,expected)&&Kad6CtEqual(expected,sig,64);}
static Kad6CryptoHooks Hooks(){Kad6CryptoHooks h{};h.ed25519_sign=&Sign;h.ed25519_verify=&Verify;return h;}

static K6Publish Publish(bool sign=true){
    K6Publish p;p.record_kind=K6RecordKind::Source;p.network_mask=kK6PublishNetKad2|kK6PublishNetKad6;
    p.flags=sign?kK6PublishFlagSigned:0;p.requested_ttl_s=3600;p.record_epoch=9;
    for(Byte i=0;i<16;++i){p.target_hash[i]=i+1;p.source_id[i]=0x40+i;}
    p.record={1,2,3,4,5};for(Byte i=0;i<64;++i)p.signature[i]=0x80+i;return p;
}
static K6PublishSchedule Item(std::uint64_t id,Byte endpoint=1,Byte hash=2){K6PublishSchedule i;i.publish_lease_id=id;i.endpoint[0]=endpoint;i.target_hash[0]=hash;i.record_class=1;i.due_at=100;i.expires_at=1000;return i;}

int main(){
    K6Publish p=Publish();std::vector<Byte>w;CHECK(EncodeK6Publish(p,w)==Kad6Status::Ok,"encode signed publish");
    CHECK(w.size()==kK6PublishFixedSize+p.record.size()+64,"signed publish exact size");K6Publish d;std::size_t used=0;
    CHECK(DecodeK6Publish(w.data(),w.size(),d,&used)==Kad6Status::Ok&&used==w.size(),"decode publish");
    CHECK(d.record==p.record&&d.signature==p.signature,"publish round trip");
    Byte signKey[32];for(Byte i=0;i<32;++i)signKey[i]=0x30+i;
    CHECK(SignK6Publish(Hooks(),signKey,sizeof signKey,p,w)==Kad6Status::Ok,"sign publish");
    CHECK(VerifyK6Publish(Hooks(),signKey,p)==Kad6Status::Ok,"verify publish");
    p.record[0]^=1;CHECK(VerifyK6Publish(Hooks(),signKey,p)==Kad6Status::AuthFailed,"tampered publish rejected");p.record[0]^=1;
    for(std::size_t n=0;n<kK6PublishFixedSize;++n)CHECK(DecodeK6Publish(w.data(),n,d)==Kad6Status::Truncated,"publish prefix truncation");
    p=Publish(false);CHECK(EncodeK6Publish(p,w)==Kad6Status::Ok&&w.size()==kK6PublishFixedSize+p.record.size(),"unsigned omits signature");
    p.record.resize(kK6PublishMaxRecordBytes+1);CHECK(EncodeK6Publish(p,w)==Kad6Status::TooLarge,"publish record cap");

    K6PublishAck a;a.status=K6PublishStatus::RemoteAck;a.published_networks=kK6PublishNetKad2;a.replica_count=4;
    a.effective_ttl_s=3600;a.publish_lease_id=55;a.record_epoch=9;a.refresh_after_s=1800;a.error_detail="aceptado";
    CHECK(EncodeK6PublishAck(a,w)==Kad6Status::Ok,"encode ack");K6PublishAck ad;
    CHECK(DecodeK6PublishAck(w.data(),w.size(),ad,&used)==Kad6Status::Ok&&ad.error_detail=="aceptado","ack round trip");
    a.error_detail.assign("bad\0utf8",8);CHECK(EncodeK6PublishAck(a,w)==Kad6Status::BadValue,"ack embedded nul rejected");
    K6PublishAck reject;reject.status=K6PublishStatus::Rejected;reject.error_detail="quota";CHECK(EncodeK6PublishAck(reject,w)==Kad6Status::Ok,"rejected ack canonical");

    K6Unpublish u;u.publish_lease_id=55;u.record_epoch=10;u.target_hash=Publish().target_hash;u.source_id=Publish().source_id;
    CHECK(EncodeK6Unpublish(u,w)==Kad6Status::Ok&&w.size()==56,"unpublish exact");K6Unpublish ud;
    CHECK(DecodeK6Unpublish(w.data(),w.size(),ud,&used)==Kad6Status::Ok&&used==56,"unpublish round trip");

    K6PublishBudgetConfig cfg;cfg.window_seconds=10;cfg.total_per_window=4;cfg.endpoint_per_window=2;cfg.hash_per_window=3;cfg.custodian_per_window=3;cfg.record_class_per_window=4;
    K6PublishBudget budget(cfg);K6PublishBudgetKey key;key.endpoint[0]=1;key.target_hash[0]=2;key.custodian[0]=3;key.record_class=1;
    CHECK(budget.Admit(key,1)&&budget.Admit(key,2),"endpoint first two admitted");
    CHECK(!budget.Admit(key,3),"endpoint cap enforced");key.endpoint[0]=2;CHECK(budget.Admit(key,3),"new endpoint admitted");
    CHECK(!budget.Admit(key,4),"hash cap enforced");key.target_hash[0]=9;key.custodian[0]=4;CHECK(budget.Admit(key,4),"fourth total admitted");
    key.endpoint[0]=3;key.target_hash[0]=8;key.custodian[0]=7;CHECK(!budget.Admit(key,4),"total cap enforced");
    CHECK(budget.Admit(key,11),"window resets");budget.NoteOverload(11);CHECK(budget.AdmissionPermille(12)==250,"overload lowers admission");
    K6PublishBudget overload(cfg);overload.NoteOverload(1);CHECK(overload.Admit(key,1)&&!overload.Admit(key,2),"overload quarters total budget");

    K6PublishCoalescer c;std::uint64_t effective=0;CHECK(c.Enqueue(Item(1),0,effective)&&effective==1,"first publish queued");
    CHECK(!c.Enqueue(Item(2),0,effective)&&effective==1&&c.Size()==1,"identical publish coalesced");
    K6PublishSchedule sameEndpointHash=Item(5);sameEndpointHash.record_class=9;
    CHECK(!c.Enqueue(sameEndpointHash,0,effective)&&effective==1&&c.Size()==1,"record class cannot evade endpoint/hash coalesce");
    CHECK(c.Enqueue(Item(3,1,3),0,effective)&&c.Size()==2,"different hash separate");
    CHECK(c.TakeDue(99,10).empty(),"not due retained");auto due=c.TakeDue(100,10);CHECK(due.size()==2,"due publishes drained");
    CHECK(due[0].members==3||due[1].members==3,"coalesced member count");
    CHECK(c.Enqueue(Item(4),30,effective),"jitter item queued");CHECK(c.TakeDue(99,10).empty(),"jitter never early");CHECK(c.Expire(1000)==1&&c.Size()==0,"coalescer expiry");

    std::printf("test_kad6_publish: %d passed, %d failed\n",g_pass,g_fail);return g_fail?1:0;
}
