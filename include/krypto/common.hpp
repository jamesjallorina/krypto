// Copyright (c) 2021 cppnetwork
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <string>
#include <chrono>
#include <exception>

#define KRYPTO_NOEXCEPT noexcept
#define KRYPTO_CONSTEXPR constexpr

#define KRYPTO_INLINE inline


namespace krypto
{

using log_clock = std::chrono::system_clock;

namespace detail
{
namespace os
{
std::string errno_str(int err_num);
}   // namespace os
}   // namespace detail

class krypto_ex : public std::exception
{
public:
    krypto_ex(const std::string &msg) : m_msg(msg)
    {}
    krypto_ex(const std::string &msg, int last_errno)
    {
        m_msg = msg + ": " + detail::os::errno_str(last_errno);
    }
    const char *what() const KRYPTO_NOEXCEPT override
    {
        return m_msg.c_str();
    }

private:
    std::string m_msg;
};

using filename_t = std::string;

}   // namespace krypto
