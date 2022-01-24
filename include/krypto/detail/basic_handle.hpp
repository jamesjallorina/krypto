// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include "basic_handle_base.hpp"
#include "ssl_helper.hpp"
#include <sys/socket.h>

namespace krypto {

namespace detail {

template <bool Serverhandle>
class basic_handle;

// handles incoming ssl connection to the server
template <>
class basic_handle<true> : public basic_handle_base
{
public:
    using handle_type = SSL*;
    using socket_type = unique_socket::underlying_type;

    explicit basic_handle(SSL *ssl) : basic_handle_base(ssl)
    {
        if(m_ssl)
            m_state = true;
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

    bool is_valid() const { return m_state; }

    handle_type native_handle() { return m_ssl; }
    socket_type socket_handle() { return m_socket.native_handle(); }

    std::string get_certificates()
    {
        using ssl_helper::certificates;
        return certificates(m_ssl);
    }

    basic_handle(basic_handle const &rhs) = delete;
    basic_handle &operator=(basic_handle const &rhs)= delete;
};

// handles connection attemp to Server 
template <>
class basic_handle<false> : public basic_handle_base
{
public:
    using handle_type = SSL*;
    using socket_type = unique_socket::underlying_type;

    explicit basic_handle(handle_type ssl) : basic_handle_base(ssl)
    {
        if(m_ssl != nullptr){
            m_state = true;
		}
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

	basic_handle(basic_handle const &rhs) = delete;
	basic_handle &operator=(basic_handle const &rhs)= delete;

	bool is_valid() const { return m_state; }

	handle_type native_handle() { return m_ssl; }
	socket_type socket_handle() { return m_socket.native_handle(); }

    std::string get_certificates()
    {
        using ssl_helper::certificates;
        return certificates(m_ssl);
    }
};

}   // namespace detail
}   // namespace krypto
