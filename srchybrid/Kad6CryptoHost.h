// Host crypto adapter for MFC-free libkad6. Private NodeIdentity key material
// remains encapsulated in NodeIdentity.cpp; the sign hook delegates to it.
#pragma once

#include "kad6/kad6_crypto.h"

kad6::Kad6CryptoHooks MakeKad6HostCryptoHooks();
