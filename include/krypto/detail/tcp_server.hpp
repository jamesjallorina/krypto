// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/detail/scope_file_descriptor.hpp>
#include <krypto/detail/socket_helper.hpp>
#include <krypto/fmt/fmt.hpp>

namespace krypto
{

namespace detail
{

template <protocol proto = PF_INET>
class tcp_server
{
public:
     tcp_server() = default;

    bool is_listening() const
    {
        return server_listening;
    }

    int fd() const
    {
        return m_socket.native_handle();
    }

    void create_listener(const int port, const int no_of_connections)
    {
        std::string portnum = std::to_string(port);
        create_listener(portnum, no_of_connections);
    }

    void create_listener(std::string const &port, const int no_of_connections)
    {
        struct addrinfo hints;
        struct addrinfo *servinfo = nullptr;
        struct addrinfo *walk = nullptr;
        int last_errno = 0;
        int result = 0;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = static_cast<int>(proto);
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        assert(server_listening == false);

        result = ::getaddrinfo(NULL, port.c_str(), &hints, &servinfo);
        if(result != 0)
        {
            auto msg = fmt::format("::getaddrinfo failed: {}", gai_strerror(result));
            throw_krypto_ex(msg);
        }

        for(walk = servinfo; walk != nullptr; walk = servinfo->ai_next)
        {
            m_socket = make_unique_socket(
                                        ::socket(walk->ai_family, walk->ai_socktype, walk->ai_protocol)
                                        );
            if(!m_socket)
            {
                last_errno = errno;
                continue;
            }

            if((result = set_socket_operations(SOL_SOCKET, SO_REUSEADDR)) == -1)
            {
                throw_krypto_ex("::setsockopt failed", errno);
            }

            if((result = bind(m_socket.native_handle(), walk->ai_addr, walk->ai_addrlen)) == -1)
            {
                last_errno = errno;
                m_socket.release();
            }
            break;
        }
        ::freeaddrinfo(servinfo);
        if(walk == nullptr)
        {
            throw_krypto_ex("server: failed to bind");
        }

        if(!m_socket)
        {
            throw_krypto_ex("server: failed", last_errno);
        }

        if((result = listen(m_socket.native_handle(), no_of_connections)) == -1)
        {
            throw_krypto_ex("::listen failed", errno);
        }

        server_listening = true;
    }

    int accept_connections(struct sockaddr_storage &their_addr, socklen_t &sin_size)
    {
        return ::accept(m_socket.native_handle(), (struct sockaddr *)&their_addr, &sin_size);
    }

    int accept_connections()
    {
        return ::accept(m_socket.native_handle(), nullptr, nullptr);
    }

    int set_socket_operations(int level, int option_name)
    {
        int enable_flag = 1;
        return ::setsockopt(m_socket.native_handle(), level, option_name, &enable_flag, sizeof(enable_flag));        
    }

    ~tcp_server() = default;

private:
    tcp_server(tcp_server const & rhs) = delete;
    tcp_server &operator=(tcp_server const & rhs) = delete;

private:
    unique_socket m_socket;
    bool server_listening = false;
};

}   // namespace detail

using tcp_server = detail::tcp_server<>;

}   // namespace krypto