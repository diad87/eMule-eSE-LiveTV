#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <array>
#include <stdexcept>

namespace ese::server {
// Two native sockets rather than a wildcard or mapped dual-stack bind. Both
// families use the same port and accept only their exact loopback address.
class LoopbackSockets {
public:
    LoopbackSockets(int type,int protocol,unsigned short port)
    {
        try {
            port_=Bind(0,type,protocol,port);
            if(Bind(1,type,protocol,port_)!=port_)
                throw std::runtime_error("IPv4 and IPv6 loopback ports differ");
        } catch(...) {
            Close();
            throw;
        }
    }
    ~LoopbackSockets() { Close(); }
    LoopbackSockets(const LoopbackSockets&) = delete;
    LoopbackSockets& operator=(const LoopbackSockets&) = delete;

    unsigned short Port() const noexcept { return port_; }
    const std::array<SOCKET,2>& Handles() const noexcept { return handles_; }

private:
    unsigned short Bind(std::size_t index,int type,int protocol,unsigned short port)
    {
        const auto family=index==0 ? AF_INET : AF_INET6;
        auto& socketHandle=handles_[index];
        socketHandle=socket(family,type,protocol);
        if(socketHandle==INVALID_SOCKET) throw std::runtime_error("open native loopback socket");
        constexpr BOOL enabled=TRUE;
        if(setsockopt(socketHandle,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,
                reinterpret_cast<const char*>(&enabled),sizeof enabled)!=0 ||
            (index!=0 && setsockopt(socketHandle,IPPROTO_IPV6,IPV6_V6ONLY,
                reinterpret_cast<const char*>(&enabled),sizeof enabled)!=0))
            throw std::runtime_error("configure exclusive loopback socket");
        if(index==0) {
            sockaddr_in address{};
            address.sin_family=AF_INET;
            address.sin_port=htons(port);
            address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
            int length=sizeof address;
            if(bind(socketHandle,reinterpret_cast<const sockaddr*>(&address),sizeof address)!=0 ||
                getsockname(socketHandle,reinterpret_cast<sockaddr*>(&address),&length)!=0 ||
                address.sin_addr.s_addr!=htonl(INADDR_LOOPBACK) || !address.sin_port)
                throw std::runtime_error("bind IPv4 loopback socket");
            return ntohs(address.sin_port);
        }
        sockaddr_in6 address{};
        address.sin6_family=AF_INET6;
        address.sin6_port=htons(port);
        address.sin6_addr=in6addr_loopback;
        int length=sizeof address;
        if(bind(socketHandle,reinterpret_cast<const sockaddr*>(&address),sizeof address)!=0 ||
            getsockname(socketHandle,reinterpret_cast<sockaddr*>(&address),&length)!=0 ||
            !IN6_IS_ADDR_LOOPBACK(&address.sin6_addr) || !address.sin6_port || address.sin6_scope_id)
            throw std::runtime_error("bind IPv6 loopback socket");
        return ntohs(address.sin6_port);
    }

    void Close() noexcept
    {
        for(const auto socketHandle:handles_)
            if(socketHandle!=INVALID_SOCKET) closesocket(socketHandle);
    }

    std::array<SOCKET,2> handles_{INVALID_SOCKET,INVALID_SOCKET};
    unsigned short port_=0;
};
}
