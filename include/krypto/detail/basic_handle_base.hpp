// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include "../common.hpp"
#include "scope_file_descriptor.hpp"

namespace krypto {

namespace detail {

class basic_handle_base
{
public:
    basic_handle_base() = default;
    explicit basic_handle_base(SSL* ssl) : m_ssl{ssl} {}

protected:
    /// prevent deleting object from this type
    ~basic_handle_base() = default;

    bool m_state = false;
    SSL *m_ssl = nullptr;
    unique_socket m_socket;
    };

}	// namespace detail
}	// namespace krypto