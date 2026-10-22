#include "EseNodeBindingCrypto.h"
#include "NodeIdentity.h"
#include "LiveCrypto.h"
#include "../cryptopp/sha.h"
namespace ese { namespace binding {
bool NodeCrypto::Hash(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,32>& out) noexcept {
    if(n && !p) return false;
    try { CryptoPP::SHA256 hash; hash.CalculateDigest(out.data(),p,n); return true; }
    catch(...) { out.fill(0); return false; }
}
bool NodeCrypto::Export(const std::array<std::uint8_t,32>& context,std::array<std::uint8_t,32>& out) noexcept {
    if(tls_.PeerExporter(context,out)) return true;
    out.fill(0); return false;
}
bool NodeCrypto::Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept {
    if(!eSELive::NodeIdentityIsPersistent() || (n && !p)) { out.fill(0); return false; }
    try {
        if(eSELive::NodeIdentitySign(p,n,out.data())) return true;
    } catch(...) {}
    out.fill(0); return false;
}
bool NodeCrypto::Verify(const std::array<std::uint8_t,32>& key,const std::uint8_t* p,
    std::size_t n,const std::uint8_t* sig) noexcept {
    if(!sig || (n && !p)) return false;
    try { return eSELive::VerifySignature(key.data(),p,n,sig); }
    catch(...) { return false; }
}
} }
