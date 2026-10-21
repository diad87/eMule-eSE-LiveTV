#include "../srchybrid/EseUtpEndpoint.h"
#include <cstdio>
int main() {
    unsigned checks=0,failures=0;
    auto check=[&](bool b) { ++checks; if(!b) ++failures; };
    sockaddr_in x{}; x.sin_family=AF_INET; x.sin_port=1234; x.sin_addr.s_addr=0x01020304;
    auto y=x;
    auto same=[&] { return ese::EqualUtpEndpoint(reinterpret_cast<sockaddr*>(&x),sizeof(x),reinterpret_cast<sockaddr*>(&y),sizeof(y)); };
    check(same()); y.sin_port++; check(!same()); y=x; y.sin_addr.s_addr++; check(!same());
    check(!ese::EqualUtpEndpoint(nullptr,0,reinterpret_cast<sockaddr*>(&x),sizeof(x)));
    for(int size=0;size<static_cast<int>(sizeof(x));++size)
        check(!ese::EqualUtpEndpoint(reinterpret_cast<sockaddr*>(&x),size,reinterpret_cast<sockaddr*>(&x),sizeof(x)));
    sockaddr_in6 a{}; a.sin6_family=AF_INET6; a.sin6_port=x.sin_port;
    auto* bytes=reinterpret_cast<unsigned char*>(&a.sin6_addr); bytes[10]=255; bytes[11]=255;
    std::memcpy(bytes+12,&x.sin_addr,4);
    auto mapped=[&] { return ese::EqualUtpEndpoint(reinterpret_cast<sockaddr*>(&a),sizeof(a),reinterpret_cast<sockaddr*>(&x),sizeof(x)); };
    check(mapped()); a.sin6_port++; check(!mapped()); a.sin6_port=x.sin_port;
    a.sin6_scope_id=1; check(!mapped()); a.sin6_scope_id=0;
    check(ese::EqualUtpEndpoint(reinterpret_cast<sockaddr*>(&x),sizeof(x),reinterpret_cast<sockaddr*>(&a),sizeof(a)));
    bytes[0]=0x20; bytes[1]=1; bytes[10]=bytes[11]=0;
    auto b=a; a.sin6_scope_id=b.sin6_scope_id=3;
    auto v6same=[&] { return ese::EqualUtpEndpoint(reinterpret_cast<sockaddr*>(&a),sizeof(a),reinterpret_cast<sockaddr*>(&b),sizeof(b)); };
    check(v6same()); b.sin6_scope_id=4; check(!v6same()); b=a; b.sin6_port++; check(!v6same());
    for(int size=0;size<static_cast<int>(sizeof(a));++size)
        check(!ese::EqualUtpEndpoint(reinterpret_cast<sockaddr*>(&a),size,reinterpret_cast<sockaddr*>(&a),sizeof(a)));
    b=a; b.sin6_family=AF_UNSPEC; check(!v6same());
    y=x; x.sin_port=0; y.sin_port=0; check(!same());
    a.sin6_port=0; b=a; check(!v6same());
    check(!ese::ValidUtpEndpoint(reinterpret_cast<sockaddr*>(&a),sizeof(sockaddr_storage)+1));
    check(!ese::ValidUtpEndpoint(nullptr,sizeof(sockaddr_storage)));
    std::printf("uTP exact endpoint: %u checks, %u failures\n",checks,failures);
    return failures ? 1 : 0;
}
