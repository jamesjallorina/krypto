// Copyright (c) 2021 cppnetwork
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <string>

namespace krypto
{
/// Here we define the KRYPTO_VERSION this should be updated on each
/// release
#define KRYPTO_VERSION v1_0_0
#define KRYPTO_VERSION_STR "1.0.0"

inline namespace KRYPTO_VERSION
{
/// @return The version of the library as string
std::string version()
{
    return KRYPTO_VERSION_STR;
}

} // namespace KRYPTO_VERSION

} // namespace krypto