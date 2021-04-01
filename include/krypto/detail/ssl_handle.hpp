// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/detail/ssl_helper.hpp>

namespace krypto
{
namespace detail
{

using ssl_helper::ossl_err_as_string;
using ssl_helper::certificates;

/*
excerpt::

template <bool Serverhandle, 
    template <class Method> class ConnectionPolicy = TLSConnect>
class ssl_handle;

template <template <class Method> class ConnectionPolicy>
class ssl_handle<true, ConnectionPolicy>
{
    // implementation here for server handle type
}

template <template <class Method> class ConnectionPolicy = TLSConnect>
class ssl_handle<false, ConnectionPolicy>
{
    // implementation here for client handle type
}


*/

template <bool Serverhandle>
class ssl_handle;

// handles incoming ssl connection to the server
template <>
class ssl_handle<true>
{
public:
    ssl_handle() = default;
    explicit ssl_handle(SSL *ssl)
    {
        if(SSL_accept(ssl) == -1)
        {
            auto msg = fmt::format("::SSL_accept failed {}", ossl_err_as_string());
            throw_krypto_ex(msg);
        }
        m_ssl = ssl;
        m_socket = make_unique_socket(::SSL_get_fd(m_ssl));
    }
    
    ssl_handle(ssl_handle && rhs) KRYPTO_NOEXCEPT
    {
        if(this != &rhs)
        {
            m_ssl = std::move(rhs.m_ssl);
            m_socket = std::move(rhs.m_socket);
            rhs.m_ssl = nullptr;
            rhs.m_socket.release();
        }
    }
    ssl_handle &operator=(ssl_handle && rhs) KRYPTO_NOEXCEPT
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
    
    ~ssl_handle()
    {
        if(m_ssl)
            ::SSL_free(m_ssl);
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
    ssl_handle(ssl_handle const &rhs) = delete;
    ssl_handle &operator=(ssl_handle const &rhs)= delete;

private:
    SSL *m_ssl = nullptr;
    unique_socket m_socket;
};

// handles connection attemp to Server 
template <>
class ssl_handle<false>
{
public:
    explicit ssl_handle(SSL *ssl)
    {
        if(SSL_accept(ssl) == -1)
        {
            auto msg = fmt::format("::SSL_accept failed {}", ossl_err_as_string());
            throw_krypto_ex(msg);
        }
        m_ssl = ssl;
        m_socket = make_unique_socket(::SSL_get_fd(m_ssl));
    }

    ssl_handle(ssl_handle && rhs) KRYPTO_NOEXCEPT
    {
        if(this != &rhs)
        {
            m_ssl = std::move(rhs.m_ssl);
            m_socket = std::move(rhs.m_socket);
            rhs.m_ssl = nullptr;
        }
    }

    ssl_handle &operator=(ssl_handle && rhs) KRYPTO_NOEXCEPT
    {
        if(this != &rhs)
        {
            m_ssl = std::move(rhs.m_ssl);
            m_socket = std::move(rhs.m_socket);
            rhs.m_ssl = nullptr;
        }
        return *this;  
    }

    ~ssl_handle()
    {
        if(m_ssl)
            ::SSL_free(m_ssl);
        m_ssl = nullptr;
    }

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
private:
    ssl_handle(ssl_handle const &rhs) = delete;
    ssl_handle &operator=(ssl_handle const &rhs)= delete;

private:
    SSL *m_ssl = nullptr;
    unique_socket m_socket;
};

}   // namespace detail

using server_handle = detail::ssl_handle<true>;
using client_handle = detail::ssl_handle<false>;

}   // namespace krypto