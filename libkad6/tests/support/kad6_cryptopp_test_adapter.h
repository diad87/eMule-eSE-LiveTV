// SPDX-License-Identifier: MIT
#pragma once

#include "kad6/kad6_crypto.h"

// Test-only host adapter. libkad6 remains provider-neutral; this proves that
// its IoC contract works with the same vendored Crypto++ used by eMule.
kad6::Kad6CryptoHooks MakeKad6CryptoPpTestHooks();
