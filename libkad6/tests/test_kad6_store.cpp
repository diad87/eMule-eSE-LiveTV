// SPDX-License-Identifier: MIT
#include "kad6/kad6_store.h"

#include <cstdio>
#include <vector>

using namespace kad6;
static int g_pass=0,g_fail=0;
#define CHECK(c,m) do{if(c)++g_pass;else{++g_fail;std::printf("  FAIL: %s (%s:%d)\n",m,__FILE__,__LINE__);}}while(0)

static K6Endpoint Endpoint(Byte host,std::uint16_t port,bool route){
    K6Endpoint e;e.addr.family=Kad6Address::Family::IPv6;
    e.addr.addr={0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,host};
    e.udp_port=port;e.tcp_port=port+1;e.transport_flags=route?kK6EpUdpKad6:(kK6EpUdpKad6|kK6EpTcpEd2k);e.valid_until=1700003600;return e;
}
static K6RouteHeader Header(){K6RouteHeader h;h.txid=7;for(Byte i=0;i<16;++i)h.sender_id[i]=0x10+i;h.sender_caps=3;h.sender_epoch=9;h.sender_endpoint=Endpoint(1,4672,true);h.sender_record.kad_id=h.sender_id;for(Byte i=0;i<32;++i)h.sender_record.node_pub[i]=0x30+i;h.sender_record.epoch=h.sender_epoch;h.sender_record.caps=h.sender_caps;h.sender_record.valid_from=1700000000;h.sender_record.valid_until=1700003600;h.sender_record.endpoints.push_back(h.sender_endpoint);h.sender_record.signature[0]=1;return h;}
static K6SourceRecord Source(){K6SourceRecord s;for(Byte i=0;i<16;++i){s.object_hash[i]=i+1;s.source_pseudonym[i]=0x20+i;s.service_token[i]=0x40+i;}s.source_epoch=12;s.created_at=1700000000;s.expires_at=1700003600;for(Byte i=0;i<32;++i){s.metadata_hash[i]=0x60+i;s.pub_key[i]=0x80+i;}K6ExitDescriptor x;for(Byte i=0;i<32;++i)x.exit_node_pub[i]=0xa0+i;x.endpoint=Endpoint(2,5000,false);x.lease_hint=44;x.caps=2;x.exit_expires_at=1700003000;x.endpoint.valid_until=x.exit_expires_at;s.exits.push_back(x);s.signature[0]=1;return s;}

int main(){
    K6StoreSourceRequest request;request.header=Header();request.record=Source();request.target_hash=request.record.object_hash;
    std::vector<Byte> wire;CHECK(EncodeK6StoreSourceRequest(request,wire)==Kad6Status::Ok,"store request encodes");
    CHECK(wire.size()<=kK6StoreMaxPayloadSize,"store request fits datagram budget");K6StoreSourceRequest decoded;
    CHECK(DecodeK6StoreSourceRequest(wire.data(),wire.size(),decoded)==Kad6Status::Ok,"store request decodes");
    CHECK(decoded.header.txid==7&&decoded.record.source_epoch==12&&decoded.target_hash==request.target_hash,"store request round trip");
    bool prefix=false;for(std::size_t n=0;n<wire.size();++n)if(DecodeK6StoreSourceRequest(wire.data(),n,decoded)==Kad6Status::Ok)prefix=true;CHECK(!prefix,"request rejects every proper prefix");
    auto trailing=wire;trailing.push_back(0);CHECK(DecodeK6StoreSourceRequest(trailing.data(),trailing.size(),decoded)==Kad6Status::Malformed,"request rejects trailing byte");
    request.target_hash[0]^=1;CHECK(EncodeK6StoreSourceRequest(request,wire)==Kad6Status::BadValue,"request target must match record");

    K6StoreSourceResponse response;response.header=Header();response.target_hash=Source().object_hash;response.status=K6StoreStatus::Stored;response.load=33;response.accepted_epoch=12;
    CHECK(EncodeK6StoreSourceResponse(response,wire)==Kad6Status::Ok,"store response encodes");K6StoreSourceResponse rd;
    CHECK(DecodeK6StoreSourceResponse(wire.data(),wire.size(),rd)==Kad6Status::Ok&&rd.status==K6StoreStatus::Stored&&rd.accepted_epoch==12,"store response round trip");
    for(std::size_t i=wire.size()-8;i<wire.size();++i)wire[i]=0;CHECK(DecodeK6StoreSourceResponse(wire.data(),wire.size(),rd)==Kad6Status::Malformed,"stored response requires epoch");
    response.load=101;CHECK(EncodeK6StoreSourceResponse(response,wire)==Kad6Status::BadValue,"response load bounded");

    K6FindSourceRequest find;find.header=Header();find.target_hash=Source().object_hash;find.max_records=4;
    CHECK(EncodeK6FindSourceRequest(find,wire)==Kad6Status::Ok,"find request encodes");K6FindSourceRequest fd;
    CHECK(DecodeK6FindSourceRequest(wire.data(),wire.size(),fd)==Kad6Status::Ok&&fd.max_records==4,"find request round trip");
    find.max_records=0;CHECK(EncodeK6FindSourceRequest(find,wire)==Kad6Status::BadValue,"find request requires bounded maximum");

    K6FindSourceResponse found;found.header=Header();found.target_hash=Source().object_hash;found.records.push_back(Source());
    CHECK(EncodeK6FindSourceResponse(found,wire)==Kad6Status::Ok,"find response encodes");K6FindSourceResponse fr;
    CHECK(DecodeK6FindSourceResponse(wire.data(),wire.size(),fr)==Kad6Status::Ok&&fr.records.size()==1&&fr.records[0].source_epoch==12,"find response round trip");
    prefix=false;for(std::size_t n=0;n<wire.size();++n)if(DecodeK6FindSourceResponse(wire.data(),n,fr)==Kad6Status::Ok)prefix=true;CHECK(!prefix,"find response rejects every proper prefix");
    found.records[0].object_hash[0]^=1;CHECK(EncodeK6FindSourceResponse(found,wire)==Kad6Status::BadValue,"find response target binds every record");
    std::printf("test_kad6_store: %d passed, %d failed\n",g_pass,g_fail);return g_fail?1:0;
}
