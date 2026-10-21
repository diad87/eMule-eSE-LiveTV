#include "../../srchybrid/EseBlockPacketBounds.h"
#include <array>
#include <cstdio>
int main() {
    unsigned checks=0,failures=0;
    auto check=[&](bool good) { ++checks; if(!good) ++failures; };
    std::array<std::uint8_t,64> bytes{};
    auto write=[&](unsigned at,std::uint64_t value,unsigned width) {
        for(unsigned i=0;i<width;++i) bytes[at+i]=static_cast<std::uint8_t>(value>>(i*8));
    };
    ese::BlockPacketBounds bounds;
    for(bool packed:{false,true}) for(bool wide:{false,true}) {
        const unsigned width=wide?8:4,header=16+width+(packed?4:width);
        for(unsigned length=0;length<=header;++length) {
            bounds={1,2,3,4};
            check(!ese::ReadBlockPacketBounds(bytes.data(),length,packed,wide,bounds) && !bounds.header);
        }
        write(16,0,width); write(16+width,3,packed?4:width);
        check(ese::ReadBlockPacketBounds(bytes.data(),header+3,packed,wide,bounds) &&
            bounds.start==0 && bounds.end==3 && bounds.payload==3 && bounds.header==header);
        if(!packed) {
            write(16+width,2,width);
            check(!ese::ReadBlockPacketBounds(bytes.data(),header+3,packed,wide,bounds));
        }
    }
    for(bool packed:{false,true}) {
        const unsigned header=packed?28:32;
        write(16,4294967294ULL,8); write(24,4294967297ULL,8);
        check(ese::ReadBlockPacketBounds(bytes.data(),header+3,packed,true,bounds) &&
            bounds.start==4294967294ULL && bounds.end==4294967297ULL);
        write(16,UINT64_MAX-1,8); write(24,UINT64_MAX,8);
        check(!ese::ReadBlockPacketBounds(bytes.data(),header+3,packed,true,bounds));
        write(16,UINT64_MAX-3,8);
        check(ese::ReadBlockPacketBounds(bytes.data(),header+3,packed,true,bounds) && bounds.end==UINT64_MAX);
    }
    check(!ese::ReadBlockPacketBounds(nullptr,64,false,true,bounds));
    std::printf("Block packet bounds: %u checks %u failures; real 64bit crossing and overflow fences\n",checks,failures);
    return failures?1:0;
}
