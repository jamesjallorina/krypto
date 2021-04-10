// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/fmt/fmt.hpp>

#include <string>
#include <chrono>
#include <exception>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define KRYPTO_NOEXCEPT noexcept
#define KRYPTO_CONSTEXPR constexpr

#define KRYPTO_INLINE inline


#ifdef KRYPTO_NO_EXCEPTIONS
#define KRYPTO_TRY
#define KRYPTO_THROW(ex)                                                                                                                   \
    do                                                                                                                                     \
    {                                                                                                                                      \
        printf("krypto fatal error: %s\n", ex.what());                                                                                     \
        std::abort();                                                                                                                      \
    } while (0)
#define KRYPTO_CATCH_ALL()
#else
#define KRYPTO_TRY try
#define KRYPTO_THROW(ex) throw(ex)
#define KRYPTO_CATCH_ALL() catch (...)
#endif


namespace krypto
{

using protocol = int;

using log_clock = std::chrono::system_clock;
using memory_buf_t = fmt::basic_memory_buffer<char, 250>;

class krypto_ex : public std::exception
{
public:
    explicit krypto_ex(const std::string &msg) : m_msg(msg)
    {}
    krypto_ex(const std::string &msg, int last_errno) 
    {
        memory_buf_t outbuf;
        fmt::format_system_error(outbuf, last_errno, msg);
        m_msg = fmt::to_string(outbuf);
    }
    const char *what() const KRYPTO_NOEXCEPT override
    {
        return m_msg.c_str();
    }

private:
    std::string m_msg;
};

using filename_t = std::string;

KRYPTO_INLINE void throw_krypto_ex(std::string msg)
{
    KRYPTO_THROW(krypto_ex(std::move(msg)));
}

KRYPTO_INLINE void throw_krypto_ex(std::string const &msg, int last_errno)
{
    KRYPTO_THROW(krypto_ex(msg, last_errno));
}

}   // namespace krypto
