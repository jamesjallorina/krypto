// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#ifndef INCLUDE_KRYPTO_HPP_
#define INCLUDE_KRYPTO_HPP_

#include <krypto/detail/scope_file_descriptor.hpp>
#include <krypto/detail/scope_thread.hpp>
#include <krypto/detail/tcp_client.hpp>
#include <krypto/detail/tcp_server.hpp>
#include <krypto/detail/ssl_server.hpp>
#include <krypto/detail/ssl_client.hpp>
#include <krypto/detail/basic_handle.hpp>
#include <krypto/detail/ssl_helper.hpp>
#include <krypto/detail/connector.hpp>
#include <krypto/detail/acceptor.hpp>

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