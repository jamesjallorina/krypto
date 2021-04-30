// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/detail/basic_handle.hpp>
#include <krypto/detail/tcp_client.hpp>

namespace krypto
{

namespace detail
{
using ssl_helper::ossl_err_as_string;
using ssl_helper::certificates;

/*
excerpt::


template <class Method> class ConnectionPolicy = TLSConnect>
class ssl_client;

template <template <class Method> class ConnectionPolicy>
class ssl_client
{
    // implementation here for client
}

*/

// reference 
// https://stackoverflow.com/questions/11705815/client-and-server-communication-using-ssl-c-c-ssl-protocol-dont-works
// http://simplestcodings.blogspot.com/2010/08/secure-server-client-using-openssl-in-c.html
class ssl_client
{
public:
    ssl_client();
    ssl_client(std::string const &certificate, 
            std::string const &key);
    
    ssl_client(ssl_client && rhs) KRYPTO_NOEXCEPT;
    ssl_client &operator=(ssl_client && rhs) KRYPTO_NOEXCEPT;

    ssl_client(ssl_client const & rhs) = delete;
    ssl_client &operator=(ssl_client const & rhs) = delete;

    ~ssl_client();

public:
    SSL *connect(
        std::string const &hostname,
        std::string const &port
        );

private:
    void init_client_context(void);
    void load_certificate(
        std::string const &certificate, 
        std::string const &key);

private:
    SSL_CTX *m_ctx = nullptr;
    std::unique_ptr<krypto::tcp_client> client;
};

ssl_client::ssl_client()
{
    init_client_context();
    client = std::make_unique<krypto::tcp_client>();
}

ssl_client::ssl_client(std::string const &certificate, 
        std::string const &key)
{
    init_client_context();
    load_certificate(certificate, key);
    client = std::make_unique<krypto::tcp_client>();
}

ssl_client::~ssl_client()
{
    if(m_ctx)
        ::SSL_CTX_free(m_ctx);
    m_ctx = nullptr;
}

ssl_client::ssl_client(ssl_client && rhs) KRYPTO_NOEXCEPT
{
    if(this != &rhs)
    {
        client = std::move(rhs.client);
        m_ctx = std::move(rhs.m_ctx);
        rhs.m_ctx = nullptr;
    }
}

ssl_client &ssl_client::operator=(ssl_client && rhs) KRYPTO_NOEXCEPT
{
    if(this != &rhs)
    {
        client = std::move(rhs.client);
        m_ctx = std::move(rhs.m_ctx);
        rhs.m_ctx = nullptr;
    }
    return *this;
}

KRYPTO_INLINE
void ssl_client::init_client_context(void)
{
    const SSL_METHOD *method = nullptr;

    ::SSL_load_error_strings();     /* Bring in and register error messages */
    ::SSL_library_init();
    //::OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */

    method = ::TLS_client_method(); /* Create new client-method instance */
    m_ctx = ::SSL_CTX_new(method);    /* Create new context */

    if(m_ctx == nullptr) 
    {
        auto msg = fmt::format("::SSL_CTX_new failed: {}", ossl_err_as_string());
        throw_krypto_ex(msg);
    }
}

KRYPTO_INLINE 
void ssl_client::load_certificate(
        std::string const &certificate, 
        std::string const &key)
{
    /* set the local certificate from CertFile */
    if (::SSL_CTX_use_certificate_file(m_ctx, certificate.data(), SSL_FILETYPE_PEM) <= 0) 
    {
        auto msg = fmt::format("::SSL_CTX_use_certificate_file failed: {}", ssl_helper::ossl_err_as_string());
        throw_krypto_ex(msg);
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (::SSL_CTX_use_PrivateKey_file(m_ctx, key.data(), SSL_FILETYPE_PEM) <= 0) 
    {
        auto msg = fmt::format("::SSL_CTX_use_PrivateKey_file failed: {}", ssl_helper::ossl_err_as_string());
        throw_krypto_ex(msg);
    }
    /* verify private key */
    if (!::SSL_CTX_check_private_key(m_ctx))
    {
        throw_krypto_ex("Private key does not match the public certificate\n");
    }
}

KRYPTO_INLINE
SSL *ssl_client::connect(
        std::string const &hostname,
        std::string const &port
    )
{
    SSL *ssl = nullptr;

    client->connect(hostname.data(), port);
    ssl = ::SSL_new(m_ctx);
    ::SSL_set_fd(ssl, client->release());
    return ssl;
}

}   // namespace detail

using ssl_client = detail::ssl_client;

}   // namespace krypto