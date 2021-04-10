// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/detail/basic_handle.hpp>

namespace krypto {
namespace detail {

KRYPTO_INLINE
void handshake(detail::basic_handle<false> &handle)
{
    if(::SSL_connect(handle.native_handle()) < 1)
    {
        auto msg = fmt::format("::SSL_connect failed {}", detail::ssl_helper::ossl_err_as_string());
        throw_krypto_ex(msg);
    }
}

}   // namespace detail
}   // namespace krypto