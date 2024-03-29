// Copyright (c) 2021-present James Marjun Jallorinana
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include "../../krypto/common.hpp"

#include <unistd.h>
#include <cassert>
#include <utility>

namespace krypto {

namespace detail {

class scope_file_descriptor
{
public:
    using underlying_type = int;

    scope_file_descriptor() KRYPTO_NOEXCEPT : 
        m_file_descriptor(-1) {}
    
    explicit scope_file_descriptor(int file_descriptor) :
        m_file_descriptor(file_descriptor)
    {
        if(file_descriptor == -1)
            throw_krypto_ex("invalid file descriptor");
    }
    
    scope_file_descriptor(scope_file_descriptor &&other) KRYPTO_NOEXCEPT
    {
        if(this != &other)
        {
            m_file_descriptor = std::move(other.m_file_descriptor);
            other.m_file_descriptor = -1;
        }
    }

    scope_file_descriptor &operator=(scope_file_descriptor &&other) KRYPTO_NOEXCEPT
    {
        if(this != &other)
        {
            m_file_descriptor = std::move(other.m_file_descriptor);
            other.m_file_descriptor = -1;
        }
        return *this;
    }

    ~scope_file_descriptor()
    {
        if(m_file_descriptor != -1)
        {
            ::close(m_file_descriptor);
        }
    }

    int native_handle() const KRYPTO_NOEXCEPT
    {
        return m_file_descriptor;
    }

    bool valid() const KRYPTO_NOEXCEPT
    {
        return (m_file_descriptor != -1);
    }

    void close() KRYPTO_NOEXCEPT
    {
        if(m_file_descriptor != -1)
        {
            ::close(m_file_descriptor);
            m_file_descriptor = -1;
        }
    }

    int release()
    {
        int file_descriptor = -1;
        if(m_file_descriptor != -1)
        {
            file_descriptor = m_file_descriptor;
            m_file_descriptor = -1;
        }
        return file_descriptor;
    }

    explicit operator bool() const KRYPTO_NOEXCEPT
    {
        return (m_file_descriptor != -1);
    }

private:
    scope_file_descriptor(scope_file_descriptor const &) = delete;
    scope_file_descriptor &operator=(scope_file_descriptor const &) = delete;

private:
    socket_type m_file_descriptor;

};

using unique_socket = scope_file_descriptor;

template <class...Ts>
unique_socket make_unique_socket(Ts&&...ts)
{
    return unique_socket(std::forward<Ts>(ts)...);
}

} // namespace detail
} // namespace krypto
