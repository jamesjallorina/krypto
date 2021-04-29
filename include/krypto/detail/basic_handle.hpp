// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/detail/ssl_helper.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include  <sys/socket.h>

namespace krypto
{

namespace detail
{

template <bool Serverhandle>
class basic_handle;

// handles incoming ssl connection to the server
template <>
class basic_handle<true>
{
public:
    using handle_type = SSL*;
    using socket_type = unique_socket::underlying_type;

    explicit basic_handle(SSL *ssl) : m_ssl{ssl}
    {
        if(m_ssl)
            state = true;
        ::SSL_set_accept_state(m_ssl);
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

    bool is_valid() const { return state; }

    handle_type native_handle() { return m_ssl; }
    socket_type socket_handle() { return m_socket.native_handle(); }

    std::string get_certificates()
    {
        using ssl_helper::certificates;
        return certificates(m_ssl);
    }

private:
    basic_handle(basic_handle const &rhs) = delete;
    basic_handle &operator=(basic_handle const &rhs)= delete;

private:
    bool state = false;
    SSL *m_ssl = nullptr;
    unique_socket m_socket;
};

// handles connection attemp to Server 
template <>
class basic_handle<false>
{
public:
    using handle_type = SSL*;
    using socket_type = unique_socket::underlying_type;

    explicit basic_handle(SSL *ssl) : m_ssl{ssl}
    {
        if(m_ssl)
            state = true;
        ::SSL_set_connect_state(m_ssl);
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

    bool is_valid() const { return state; }

    handle_type native_handle() { return m_ssl; }
    socket_type socket_handle() { return m_socket.native_handle(); }

    std::string get_certificates()
    {
        using ssl_helper::certificates;
        return certificates(m_ssl);
    }

private:
    basic_handle(basic_handle const &rhs) = delete;
    basic_handle &operator=(basic_handle const &rhs)= delete;

private:
    bool state = false;
    SSL *m_ssl = nullptr;
    unique_socket m_socket;
};

}   // namespace detail

using server_handle = detail::basic_handle<true>;
using client_handle = detail::basic_handle<false>;

}   // namespace krypto