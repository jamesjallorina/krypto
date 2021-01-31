// Copyright (c) 2021 cppnetwork
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <unistd.h>
#include <utility>

#include <krypto/common.hpp>

namespace krypto
{
namespace detail
{

class scope_file_descriptor
{
public:
    scope_file_descriptor() KRYPTO_NOEXCEPT : 
        m_file_descriptor(-1) {}
    
    scope_file_descriptor(int file_descriptor) :
        m_file_descriptor(file_descriptor)
    {
        if(m_file_descriptor == -1)
            throw krypto_ex("invalid file descriptor");
    }
    
    scope_file_descriptor(scope_file_descriptor &&other) KRYPTO_NOEXCEPT
    {
        m_file_descriptor = std::move(other.m_file_descriptor);
        other.m_file_descriptor = -1;
    }

    scope_file_descriptor &operator=(scope_file_descriptor &&other) KRYPTO_NOEXCEPT
    {
        m_file_descriptor = std::move(other.m_file_descriptor);
        other.m_file_descriptor = -1;
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

    explicit operator bool() const KRYPTO_NOEXCEPT
    {
        return (m_file_descriptor != -1);
    }

private:
    scope_file_descriptor(scope_file_descriptor const &) = delete;
    scope_file_descriptor &operator=(scope_file_descriptor const &) = delete;

private:
    int m_file_descriptor;

};
} // namespace detail

} // namespace krypto