//this file is part of eMule
// eSE — Live broadcaster identity (Ed25519 keypair, sign/verify) — impl
#include "stdafx.h"
#include "LiveCrypto.h"
#include "../cryptopp/xed25519.h"
#include "../cryptopp/osrng.h"
#include "../cryptopp/sha.h"
#include "../cryptopp/filters.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

namespace eSELive {

bool GenerateBroadcasterKeypair(uint8_t pubkey[LIVE_PUBKEY_SIZE],
                                uint8_t privkey[LIVE_PRIVKEY_SIZE])
{
    try {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::ed25519PrivateKey priv;
        priv.GenerateRandom(rng, CryptoPP::g_nullNameValuePairs);
        // ed25519PrivateKey stores secret seed (m_sk) and derived pubkey (m_pk)
        // as FixedSizeSecBlock<byte, 32>. The accessor pointers stay valid for
        // the lifetime of `priv`, so we copy out before the local goes out of
        // scope.
        memcpy(pubkey,  priv.GetPublicKeyBytePtr(),  LIVE_PUBKEY_SIZE);
        memcpy(privkey, priv.GetPrivateKeyBytePtr(), LIVE_PRIVKEY_SIZE);
        return true;
    } catch (...) {
        return false;
    }
}

bool SignMessage(const uint8_t privkey[LIVE_PRIVKEY_SIZE],
                 const uint8_t pubkey[LIVE_PUBKEY_SIZE],
                 const uint8_t* msg, size_t msgLen,
                 uint8_t sig[LIVE_SIGNATURE_SIZE])
{
    try {
        // Construct signer from raw key bytes (no PKCS8 envelope).
        CryptoPP::ed25519Signer signer(pubkey, privkey);
        CryptoPP::AutoSeededRandomPool rng;
        size_t out = signer.SignMessage(rng, msg, msgLen, sig);
        return out == LIVE_SIGNATURE_SIZE;
    } catch (...) {
        return false;
    }
}

bool VerifySignature(const uint8_t pubkey[LIVE_PUBKEY_SIZE],
                     const uint8_t* msg, size_t msgLen,
                     const uint8_t sig[LIVE_SIGNATURE_SIZE])
{
    try {
        CryptoPP::ed25519Verifier verifier(pubkey);
        return verifier.VerifyMessage(msg, msgLen, sig, LIVE_SIGNATURE_SIZE);
    } catch (...) {
        return false;
    }
}

void DeriveStreamKey(const uint8_t pubkey[LIVE_PUBKEY_SIZE],
                     uint8_t streamKey[LIVE_STREAMKEY_SIZE])
{
    // SHA1(pubkey) → 20 bytes. Truncate to 16 = streamKey.
    CryptoPP::SHA1 hash;
    uint8_t digest[20];
    hash.CalculateDigest(digest, pubkey, LIVE_PUBKEY_SIZE);
    memcpy(streamKey, digest, LIVE_STREAMKEY_SIZE);
}

bool StreamKeyMatchesPubkey(const uint8_t streamKey[LIVE_STREAMKEY_SIZE],
                            const uint8_t pubkey[LIVE_PUBKEY_SIZE])
{
    uint8_t derived[LIVE_STREAMKEY_SIZE];
    DeriveStreamKey(pubkey, derived);
    // Constant-time compare — streamKey is not a secret so it doesn't matter
    // much, but consistency with crypto code style.
    uint8_t diff = 0;
    for (size_t i = 0; i < LIVE_STREAMKEY_SIZE; ++i)
        diff |= streamKey[i] ^ derived[i];
    return diff == 0;
}

} // namespace eSELive
