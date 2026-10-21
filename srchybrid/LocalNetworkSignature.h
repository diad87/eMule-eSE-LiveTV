#pragma once
#include <iphlpapi.h>
#include <netioapi.h>
#include "natmap/network_topology_signature.h"
#include <cstring>
namespace natmap {
inline bool StoreTopologyAddress(NetworkTopologyRecord& record,std::size_t offset,const SOCKADDR* address,int length) {
    if(!address || offset>record.size()-20) return false;
    if(address->sa_family==AF_INET && length>=static_cast<int>(sizeof(SOCKADDR_IN))) {
        const auto* ipv4=reinterpret_cast<const SOCKADDR_IN*>(address);
        record[1]=4; std::memcpy(record.data()+offset,&ipv4->sin_addr,4); return true;
    }
    if(address->sa_family==AF_INET6 && length>=static_cast<int>(sizeof(SOCKADDR_IN6))) {
        const auto* ipv6=reinterpret_cast<const SOCKADDR_IN6*>(address);
        record[1]=6; std::memcpy(record.data()+offset,&ipv6->sin6_addr,16);
        SetTopologyInteger(record,offset+16,ipv6->sin6_scope_id,4); return true;
    }
    return false;
}
inline std::uint64_t ReadLocalNetworkSignature() {
    ULONG bytes=0;
    constexpr ULONG flags=GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER;
    if(::GetAdaptersAddresses(AF_UNSPEC,flags,nullptr,nullptr,&bytes)!=ERROR_BUFFER_OVERFLOW || !bytes || bytes>1024*1024) return 0;
    std::vector<BYTE> buffer(bytes);
    auto adapters=reinterpret_cast<PIP_ADAPTER_ADDRESSES_LH>(buffer.data());
    if(::GetAdaptersAddresses(AF_UNSPEC,flags,nullptr,reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapters),&bytes)!=NO_ERROR) return 0;
    CanonicalNetworkTopology topology;
    for(auto adapter=adapters;adapter;adapter=adapter->Next) {
        if(adapter->Length<offsetof(IP_ADAPTER_ADDRESSES_LH,Ipv6Metric)+sizeof(adapter->Ipv6Metric)) return 0;
        if(adapter->OperStatus!=IfOperStatusUp) continue;
        for(auto unicast=adapter->FirstUnicastAddress;unicast;unicast=unicast->Next) {
            if(unicast->Length<offsetof(IP_ADAPTER_UNICAST_ADDRESS_LH,OnLinkPrefixLength)+sizeof(unicast->OnLinkPrefixLength)) return 0;
            if(unicast->DadState!=IpDadStatePreferred && unicast->DadState!=IpDadStateDeprecated) continue;
            NetworkTopologyRecord record{}; record[0]=1;
            if(!StoreTopologyAddress(record,14,unicast->Address.lpSockaddr,unicast->Address.iSockaddrLength)) continue;
            SetTopologyInteger(record,2,record[1]==6 ? adapter->Ipv6IfIndex : adapter->IfIndex,4);
            SetTopologyInteger(record,6,adapter->Luid.Value,8);
            record[34]=unicast->OnLinkPrefixLength; record[35]=static_cast<std::uint8_t>(unicast->DadState);
            SetTopologyInteger(record,56,record[1]==6 ? adapter->Ipv6Metric : adapter->Ipv4Metric,4);
            if(!topology.Add(record)) return 0;
        }
    }
    PMIB_IPFORWARD_TABLE2 routes=nullptr;
    if(::GetIpForwardTable2(AF_UNSPEC,&routes)!=NO_ERROR || !routes) return 0;
    struct RouteOwner { PMIB_IPFORWARD_TABLE2 table; ~RouteOwner() { ::FreeMibTable(table); } } owner{routes};
    if(routes->NumEntries>4096) return 0;
    for(ULONG i=0;i<routes->NumEntries;++i) {
        const auto& row=routes->Table[i];
        if(!row.ValidLifetime) continue;
        NetworkTopologyRecord record{}; record[0]=2;
        if(!StoreTopologyAddress(record,14,reinterpret_cast<const SOCKADDR*>(&row.DestinationPrefix.Prefix),sizeof(SOCKADDR_INET))) continue;
        const auto family=record[1];
        if(!StoreTopologyAddress(record,36,reinterpret_cast<const SOCKADDR*>(&row.NextHop),sizeof(SOCKADDR_INET)) || record[1]!=family) continue;
        SetTopologyInteger(record,2,row.InterfaceIndex,4); SetTopologyInteger(record,6,row.InterfaceLuid.Value,8);
        record[34]=row.DestinationPrefix.PrefixLength; SetTopologyInteger(record,56,row.Metric,4);
        if(!topology.Add(record)) return 0;
    }
    return topology.Signature(); // Sorted/deduplicated; excludes lifetimes and ages.
}
}
