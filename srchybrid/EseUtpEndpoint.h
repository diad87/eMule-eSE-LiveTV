#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>
namespace ese {
inline bool ValidUtpEndpoint(const sockaddr* p,int size) noexcept {
    if(!p || size<static_cast<int>(sizeof(p->sa_family)) || size>static_cast<int>(sizeof(sockaddr_storage))) return false;
    if(p->sa_family==AF_INET)
        return size>=static_cast<int>(sizeof(sockaddr_in)) && reinterpret_cast<const sockaddr_in*>(p)->sin_port!=0;
    if(p->sa_family==AF_INET6)
        return size>=static_cast<int>(sizeof(sockaddr_in6)) && reinterpret_cast<const sockaddr_in6*>(p)->sin6_port!=0;
    return false;
}
inline bool EqualUtpEndpoint(const sockaddr* a,int alen,const sockaddr* b,int blen) noexcept {
    if(!ValidUtpEndpoint(a,alen) || !ValidUtpEndpoint(b,blen)) return false;
    if(a->sa_family==AF_INET && b->sa_family==AF_INET) {
        const auto& x=*reinterpret_cast<const sockaddr_in*>(a);
        const auto& y=*reinterpret_cast<const sockaddr_in*>(b);
        return x.sin_port==y.sin_port && x.sin_addr.s_addr==y.sin_addr.s_addr;
    }
    if(a->sa_family==AF_INET6 && b->sa_family==AF_INET6) {
        const auto& x=*reinterpret_cast<const sockaddr_in6*>(a);
        const auto& y=*reinterpret_cast<const sockaddr_in6*>(b);
        return x.sin6_port==y.sin6_port && x.sin6_scope_id==y.sin6_scope_id &&
            std::memcmp(&x.sin6_addr,&y.sin6_addr,sizeof(in6_addr))==0;
    }
    const auto& v4=*reinterpret_cast<const sockaddr_in*>(a->sa_family==AF_INET ? a : b);
    const auto& v6=*reinterpret_cast<const sockaddr_in6*>(a->sa_family==AF_INET6 ? a : b);
    return !v6.sin6_scope_id && IN6_IS_ADDR_V4MAPPED(&v6.sin6_addr) && v4.sin_port==v6.sin6_port &&
        std::memcmp(&v4.sin_addr,reinterpret_cast<const unsigned char*>(&v6.sin6_addr)+12,4)==0;
}
}
