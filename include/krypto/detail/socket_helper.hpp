// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/common.hpp>

#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/tcp.h>

namespace krypto
{
namespace detail
{
namespace socket_helper
{

KRYPTO_INLINE void *get_in_addr(const struct sockaddr *sa)
{
    if(sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

KRYPTO_INLINE std::string network_to_printable_format(const struct sockaddr *addr)
{
    int last_errno = 0;
    char buf[INET6_ADDRSTRLEN] = {0};
    KRYPTO_CONSTEXPR auto buflen = sizeof(buf);

    if(::inet_ntop(addr->sa_family, get_in_addr((struct sockaddr *)addr), buf, buflen) == nullptr)
    {
        last_errno = errno;
        throw_krypto_ex("::inet_ntop failed: ", last_errno);
    }
    return std::string(buf);
}

KRYPTO_INLINE unsigned char *printable_to_network_format(const int domain, 
                                                        std::string const &source)
{
    int last_errno = 0;
    int result = 0;
    static unsigned char buf[sizeof(struct in6_addr)] = {0};

    result = ::inet_pton(domain, source.c_str(), buf);
    if(result <= 0)
    {
        if(result == 0)
        {
            throw_krypto_ex("::inet_pton failed: not in presentation format");
        }
        else
        {
            last_errno = errno;
            throw_krypto_ex("::inet_pton failed: ", last_errno);
        }
    }
    return buf;
}

template<typename StreamBuffer>
KRYPTO_INLINE size_t send(unique_socket &usocket, const StreamBuffer *data, size_t n_bytes, int flags = 0)
{
    static_assert(krypto::is_valid_buffer<StreamBuffer>::value, "StreamBuffer should be a valid buffer");
    int write_result = 0;
    size_t bytes_sent = 0;

    if(!usocket)
    {
        throw_krypto_ex("::send invalid socket file descriptor");
    }

    while(bytes_sent < n_bytes)
    {
        write_result = ::send(usocket.native_handle(), data + bytes_sent, n_bytes - bytes_sent, flags);
        if(write_result == -1)
        {
            usocket.release();
            throw_krypto_ex("::send failed", errno);
        }
        if(write_result == 0)   // if send returns 0 break anyway
        {
            break;
        }
        bytes_sent += static_cast<size_t>(write_result);
    }
    return bytes_sent;
}

template<typename StreamBuffer>
KRYPTO_INLINE size_t recv(unique_socket &usocket, StreamBuffer *data, size_t n_bytes, int flags = 0)
{
    static_assert(krypto::is_valid_buffer<StreamBuffer>::value, "StreamBuffer should be a valid buffer");

    int recv_result = 0;
    size_t recv_bytes = 0;

    if(!usocket)
    {
        throw_krypto_ex("::recv invalid socket file descriptor");
    }

    while(recv_bytes < n_bytes)
    {
        recv_result = ::recv(usocket.native_handle(), data + recv_bytes, n_bytes - recv_bytes, flags);

        if(recv_result == -1)
        {
            usocket.release();
            throw_krypto_ex("::recv failed", errno);
        }

        if(recv_result == 0)    // if recv returns 0 break anyway
        {
            break;
        }
        recv_bytes += static_cast<size_t>(recv_result);
    }
    return recv_bytes;
}

}   // namespace socket_helper
}   // namespace detail
}   // namespace krypto