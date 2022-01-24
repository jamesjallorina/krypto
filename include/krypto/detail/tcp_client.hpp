// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include "scope_file_descriptor.hpp"
#include "socket_helper.hpp"
#include "../fmt/fmt.hpp"


namespace krypto
{

namespace detail
{

template <protocol proto = PF_INET>
class tcp_client
{

public:
    tcp_client() = default;

    bool is_connected() const
    {
        return (m_socket.native_handle() != -1);
    }

    void close()
    {
        if(is_connected())
        {
            m_socket.close();
        }
    }

    int release()
    {
        return m_socket.release();
    }

    int fd() const
    {
        return m_socket.native_handle();
    }

    void connect(std::string const &ip_addr, std::string const &port)
    {
        struct addrinfo hints = {0};
        struct addrinfo *servinfo = nullptr;
        struct addrinfo *walk = nullptr;
        int last_errno = 0;
        int result = 0;

        std::memset(&hints, 0, sizeof hints);
        hints.ai_family = static_cast<int>(proto);        // IP version-agnostic
        hints.ai_socktype = SOCK_STREAM;    // TCP SOCKET STREAM

        result = ::getaddrinfo(ip_addr.c_str(), port.c_str(), &hints, &servinfo);
        if(result != 0)
        {
            auto msg = fmt::format("::getaddrinfo failed: {}", gai_strerror(result));
            throw_krypto_ex(msg);
        }

        for(walk = servinfo; walk != nullptr; walk = servinfo->ai_next)
        {
            m_socket = make_unique_socket
                    (
                    ::socket(walk->ai_family, walk->ai_socktype, walk->ai_protocol)
                    );

            // check if socket is valid with the use of operator bool of scope_file_descriptor
            if(!m_socket)
            {
                last_errno = errno;
                continue; 
            }

            result = ::connect(m_socket.native_handle(), walk->ai_addr, walk->ai_addrlen);
            if(result == -1)
            {
                last_errno = errno;
                m_socket.close();
                continue;
            }
            break;
        }
        ::freeaddrinfo(servinfo);
        if(walk == nullptr)
        {
            throw_krypto_ex("client: failed to connect");
        }

        if(!m_socket.valid())
        {
            throw_krypto_ex("client: failed", last_errno);
        }
    }

    int set_socket_operation(int level, int option_name)
    {
        int enable_flag = 1;
        return ::setsockopt(m_socket.native_handle(), level, option_name, &enable_flag, sizeof(enable_flag));
    }

    template <typename CharT>
    size_t send(CharT *data, size_t n_bytes, int flags = 0)
    {
        return socket_helper::send(m_socket, data, n_bytes, flags);
    }

    template <typename CharT>
    size_t recv(CharT *data, size_t n_bytes, int flags = 0)
    {
        return socket_helper::recv(m_socket, data, n_bytes, flags);
    }

    ~tcp_client() = default;
private:
    tcp_client(tcp_client const &rhs) = delete;
    tcp_client &operator=(tcp_client const &rhs) = delete;

private:
    unique_socket m_socket;
};

}   // namespace detail

using tcp_client = detail::tcp_client<>;

}   // namespace krypto
