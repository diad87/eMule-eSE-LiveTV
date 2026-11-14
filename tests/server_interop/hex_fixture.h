#pragma once
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace server_test {
inline void Check(bool condition,const char* message)
{
    if(!condition) throw std::runtime_error(message);
}

inline std::vector<std::uint8_t> LoadFixture(const std::filesystem::path& path)
{
    std::ifstream input(path);
    std::string wire,trailing;
    Check(bool(input>>wire) && !(input>>trailing) && wire.size()%2==0,"fixture readable, exactly one hex record");
    std::vector<std::uint8_t> result;
    for(std::size_t i=0;i<wire.size();i+=2) {
        const auto byte=wire.substr(i,2);
        Check(byte.find_first_not_of("0123456789abcdef")==std::string::npos,"canonical fixture hex");
        result.push_back(static_cast<std::uint8_t>(std::stoul(byte,nullptr,16)));
    }
    return result;
}
}
