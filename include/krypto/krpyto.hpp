// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#ifndef INCLUDE_KRYPTO_HPP_
#define INCLUDE_KRYPTO_HPP_

#include <krypto/core.hpp>

namespace krypto
{
// declare all public krpyto library APIs here

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