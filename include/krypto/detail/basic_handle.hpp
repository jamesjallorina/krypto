// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/detail/ssl_helper.hpp>

#include  <sys/socket.h>

namespace krypto
{
namespace detail
{

using ssl_helper::ossl_err_as_string;
using ssl_helper::certificates;

template <bool Serverhandle>
class basic_handle;

// handles incoming ssl connection to the server
template <>
class basic_handle<true>
{
public:
    explicit basic_handle(SSL *ssl) : m_ssl{ssl}
    {
        //::SSL_CTX_set_verify(::SSL_get_SSL_CTX(m_ssl), SSL_VERIFY_PEER, NULL);
        if(::SSL_accept(m_ssl) <= 0)
        {
            auto msg = fmt::format("::SSL_accept failed {}", ossl_err_as_string());
            throw_krypto_ex(msg);
        }
        m_socket = make_unique_socket(::SSL_get_fd(m_ssl));
    }
    
    basic_handle(basic_handle && rhs) KRYPTO_NOEXCEPT
    {
        if(this != &rhs)
        {
            m_ssl = std::move(rhs.m_ssl);
            m_socket = std::move(rhs.m_socket);
            rhs.m_ssl = nullptr;
            rhs.m_socket.release();
        }
    }
    basic_handle &operator=(basic_handle && rhs) KRYPTO_NOEXCEPT
    {
        if(this != &rhs)
        {
            m_ssl = std::move(rhs.m_ssl);
            m_socket = std::move(rhs.m_socket);
            rhs.m_ssl = nullptr;
            rhs.m_socket.release();
        }
        return *this;
    }
    
    ~basic_handle()
    {
        if(m_ssl)
        {
            ::SSL_shutdown(m_ssl);
            ::SSL_free(m_ssl);
        }
        m_ssl = nullptr;
    }

    SSL *native_handle() { return m_ssl; }

    template <typename StreamBuf>
    size_t read(StreamBuf *buf, int len)
    {
        size_t result = 0;
        try
        {
            result = ssl_helper::read(m_ssl, buf, len);
        }
        catch(const krypto_ex & e)
        {
            throw;
        }
        return result;
    }

    template<typename StreamBuf>
    size_t write(StreamBuf *buf, int len)
    {
        size_t result = 0;
        try
        {
            result = ssl_helper::write(m_ssl, buf, len);
        }
        catch(const krypto_ex & e)
        {
            throw;
        }
        return result;
    }

    std::string get_certificates() const
    {
        return certificates(m_ssl);
    }

private:
    basic_handle(basic_handle const &rhs) = delete;
    basic_handle &operator=(basic_handle const &rhs)= delete;

private:
    SSL *m_ssl = nullptr;
    unique_socket m_socket;
};

// handles connection attemp to Server 
template <>
class basic_handle<false>
{
public:
    explicit basic_handle(SSL *ssl) : m_ssl{ssl}
    {
        int result = 0;
        if((result = ::SSL_connect(m_ssl)) < 1)
        {
            result = ::SSL_get_error(m_ssl, result);
            auto msg = fmt::format("::SSL_connect failed {}", ossl_err_as_string());
            if(result == 5)
            {
                msg += fmt::format("SSL_get_error: 5");
            }
            throw_krypto_ex(msg);
        }
        m_socket = make_unique_socket(::SSL_get_fd(m_ssl));
    }

    basic_handle(basic_handle && rhs) KRYPTO_NOEXCEPT
    {
        if(this != &rhs)
        {
            m_ssl = std::move(rhs.m_ssl);
            m_socket = std::move(rhs.m_socket);
            rhs.m_ssl = nullptr;
            rhs.m_socket.release();
        }
    }

    basic_handle &operator=(basic_handle && rhs) KRYPTO_NOEXCEPT
    {
        if(this != &rhs)
        {
            m_ssl = std::move(rhs.m_ssl);
            m_socket = std::move(rhs.m_socket);
            rhs.m_ssl = nullptr;
            rhs.m_socket.release();
        }
        return *this;  
    }

    ~basic_handle()
    {
        if(m_ssl)
        {
            ::SSL_shutdown(m_ssl);
            ::SSL_free(m_ssl);
        }
        m_ssl = nullptr;
    }

    SSL *native_handle() { return m_ssl; }

    template <typename StreamBuf>
    size_t ssl_read(StreamBuf *buf, int len)
    {
        size_t result = 0;
        try
        {
            result = ssl_helper::read(m_ssl, buf, len);
        }
        catch(const krypto_ex & e)
        {
            throw;
        }
        return result;
    }

    template<typename StreamBuf>
    size_t ssl_write(StreamBuf *buf, int len)
    {
        size_t result = 0;
        try
        {
            result = ssl_helper::write(m_ssl, buf, len);
        }
        catch(const krypto_ex & e)
        {
            throw;
        }
        return result;
    }

    std::string get_certificates() const
    {
        return certificates(m_ssl);
    }

private:
    basic_handle(basic_handle const &rhs) = delete;
    basic_handle &operator=(basic_handle const &rhs)= delete;

private:
    SSL *m_ssl = nullptr;
    unique_socket m_socket;
};

}   // namespace detail

using server_handle = detail::basic_handle<true>;
using client_handle = detail::basic_handle<false>;

}   // namespace krypto