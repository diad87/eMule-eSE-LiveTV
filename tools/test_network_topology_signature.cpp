#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "../srchybrid/LocalNetworkSignature.h"
#include <cstdio>
#include <cstdlib>
static unsigned checks=0;
static void Check(bool value) { ++checks; if(!value) std::exit(1); }
int main() {
    natmap::NetworkTopologyRecord a{},b{}; a[0]=1; a[1]=4; b[0]=1; b[1]=6;
    natmap::SetTopologyInteger(a,2,0x12345678,4);
    Check(a[2]==0x12 && a[5]==0x78);
    natmap::SetTopologyInteger(b,6,0xFEDCBA9876543210ULL,8);
    Check(b[6]==0xFE && b[13]==0x10);
    natmap::CanonicalNetworkTopology first,permuted,empty;
    Check(empty.Signature()==0);
    Check(first.Add(a)); Check(first.Add(b));
    Check(permuted.Add(b)); Check(permuted.Add(a)); Check(permuted.Add(a));
    const auto signature=first.Signature(); Check(signature!=0); Check(signature==permuted.Signature());
    for(const auto offset:{1U,2U,6U,14U,30U,34U,35U,36U,52U,56U}) {
        auto modified=b; modified[offset]^=1;
        natmap::CanonicalNetworkTopology changed; Check(changed.Add(a)); Check(changed.Add(modified));
        Check(changed.Signature()!=signature);
    }
    natmap::CanonicalNetworkTopology full;
    for(unsigned i=0;i<4096;++i) Check(full.Add(a));
    Check(!full.Add(a)); Check(full.Signature()==0);
    SOCKADDR_IN6 ipv6{}; ipv6.sin6_family=AF_INET6; ipv6.sin6_addr.u.Byte[15]=1; ipv6.sin6_scope_id=9;
    natmap::NetworkTopologyRecord address{};
    Check(natmap::StoreTopologyAddress(address,14,reinterpret_cast<SOCKADDR*>(&ipv6),sizeof(ipv6)));
    Check(address[1]==6 && address[29]==1 && address[33]==9);
    Check(!natmap::StoreTopologyAddress(address,60,reinterpret_cast<SOCKADDR*>(&ipv6),sizeof(ipv6)));
    Check(!natmap::StoreTopologyAddress(address,14,reinterpret_cast<SOCKADDR*>(&ipv6),1));
    const auto actual=natmap::ReadLocalNetworkSignature();
    std::printf("network topology signature: %u checks PASS; live OS signature=%llu (read-only, not roaming acceptance)\n",checks,static_cast<unsigned long long>(actual));
}
