// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#ifndef INCLUDE_KRYPTO_HPP_
#define INCLUDE_KRYPTO_HPP_

#include "core.hpp"

#define KRYPTO_VERSION_MAJOR 1
#define KRYPTO_VERSION_MINOR 0
#define KRYPTO_VERSION_PATCH 0

namespace krypto
{
// declare all public krpyto library APIs here

/// @brief handle for ssl server
using server_handle = detail::basic_handle<true>;

/// @brief handle for ssl client
using client_handle = detail::basic_handle<false>;

void handshake(server_handle &handle)
{
    detail::handshake(handle);
}

void handshake(client_handle &handle)
{
    detail::handshake(handle);
}

} // namespace krypto

#endif // INCLUDE_KRYPTO_HPP_
