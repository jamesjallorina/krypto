// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/common.hpp>
#include <krypto/detail/scope_file_descriptor.hpp>
#include <krypto/fmt/fmt.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace krypto
{

namespace detail
{

namespace ssl_helper
{

inline char *ossl_err_as_string(void)
{ 
    BIO *bio = ::BIO_new (::BIO_s_mem ());
    ::ERR_print_errors (bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data (bio, &buf);
    char *ret = (char *) ::calloc (1, 1 + len);
    
    if (ret)
        ::memcpy (ret, buf, len);
    ::BIO_free (bio);
    return ret;
}

class ssl_handle
{
public:
    ssl_handle() = default;
    ssl_handle(SSL *ssl);
    ssl_handle(ssl_handle && rhs) KRYPTO_NOEXCEPT;
    ssl_handle &operator=(ssl_handle && rhs) KRYPTO_NOEXCEPT;
    ~ssl_handle();

    SSL *native_handle() { return m_ssl; }

public:
    ssl_handle(ssl_handle const &rhs) = delete;
    ssl_handle &operator=(ssl_handle const &rhs)= delete;

private:
    unique_socket m_socket;
    SSL *m_ssl = nullptr;
};

ssl_handle::ssl_handle(SSL *ssl)
{
    if(SSL_accept(ssl) == -1)
    {
        auto msg = fmt::format("::SSL_accept failed {}", ossl_err_as_string());
        throw_krypto_ex("invalid ssl handle");
    }
    m_ssl = ssl;
    m_socket = make_unique_socket(::SSL_get_fd(m_ssl));
}

ssl_handle::~ssl_handle()
{
    if(m_ssl)
        SSL_free(m_ssl);
    m_ssl = nullptr;
}

ssl_handle::ssl_handle(ssl_handle && rhs) KRYPTO_NOEXCEPT
{
    if(this != &rhs)
    {
        m_ssl = std::move(rhs.m_ssl);
        m_socket = std::move(rhs.m_socket);
        rhs.m_ssl = nullptr;
        rhs.m_socket.release();
    }
}

ssl_handle &ssl_handle::operator=(ssl_handle &&rhs) KRYPTO_NOEXCEPT
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

}   // namespace ssl_helper

}   // namespace detail

using ssl_handle = detail::ssl_helper::ssl_handle;

}   // namepsace krypto