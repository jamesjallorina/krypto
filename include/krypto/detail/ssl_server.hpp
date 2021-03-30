// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/common.hpp>
#include <krypto/detail/tcp_server.hpp>
#include <krypto/detail/ssl_helper.hpp>

namespace krypto
{

namespace detail
{

//references
// https://stackoverflow.com/questions/11705815/client-and-server-communication-using-ssl-c-c-ssl-protocol-dont-works
// http://simplestcodings.blogspot.com/2010/08/secure-server-client-using-openssl-in-c.html
class ssl_server
{

public:
    ssl_server() = delete;
    ssl_server(std::string const &port_number, 
                const int no_of_connections,
                std::string const &certificate,
                std::string const &key
                );
    ssl_server(const int port_number, 
                const int no_of_connections,
                std::string const &certificate,
                std::string const &key
                );
    ssl_server(ssl_server && rhs) KRYPTO_NOEXCEPT;
    ssl_server &operator=(ssl_server &&rhs) KRYPTO_NOEXCEPT;
    ~ssl_server();

    ssl_server(ssl_server const &rhs) = delete;
    ssl_server &operator=(ssl_server const & rhs) = delete;

public:
    SSL *accept_connections();
    SSL *accept_connections(
        struct sockaddr_storage &their_addr, 
        socklen_t &sin_size);

private:
    SSL_CTX *init_server_ctx(void);
    void load_certificates(
        std::string const &certificate, 
        std::string const &key);

private:
    SSL_CTX *ctx = nullptr;
    std::unique_ptr<krypto::tcp_server> server;
};

ssl_server::ssl_server(
    std::string const &port_number, 
    const int no_of_connections,
    std::string const &certificate,
    std::string const &key
    )
{
    using krypto::tcp_server;
    SSL_library_init();
    server = std::make_unique<tcp_server>();
    try
    {
        init_server_ctx();
        load_certificates(certificate, key);
    }
    catch(const krypto_ex & ex)
    {
        throw;
    }
    server->create_listener(port_number, no_of_connections);
}

ssl_server::ssl_server(
    const int port_number, 
    const int no_of_connections,
    std::string const &certificate,
    std::string const &key
    )
{
    std::string port = std::to_string(port_number);
    ssl_server(port, no_of_connections, certificate, key);
}

ssl_server::ssl_server(ssl_server && rhs) KRYPTO_NOEXCEPT
{
    if(this != &rhs)
    {
        ctx = std::move(rhs.ctx);
        server = std::move(rhs.server);
    }
}

ssl_server &ssl_server::operator=(ssl_server && rhs) KRYPTO_NOEXCEPT
{
    if(this != &rhs)
    {
        ctx = std::move(rhs.ctx);
        server = std::move(rhs.server);
    }
    return *this; 
}

ssl_server::~ssl_server()
{
    if(ctx)
        ::SSL_CTX_free(ctx);
    ctx = nullptr;
}

KRYPTO_INLINE
SSL *ssl_server::accept_connections()
{
    SSL *ssl = nullptr;
    unique_socket client_socket;

    client_socket = make_unique_socket(server->accept_connections());
    ssl = ::SSL_new(ctx);
    ::SSL_set_fd(ssl, client_socket.native_handle());
    return ssl;
}

KRYPTO_INLINE
SSL *ssl_server::accept_connections(
    struct sockaddr_storage &their_addr, 
    socklen_t &sin_size)
{
    SSL *ssl = nullptr;
    unique_socket client_socket;

    client_socket = make_unique_socket(server->accept_connections(their_addr, sin_size));
    ssl = ::SSL_new(ctx);
    ::SSL_set_fd(ssl, client_socket.native_handle());
    return ssl;
}

KRYPTO_INLINE 
SSL_CTX *ssl_server::init_server_ctx(void)
{
    const SSL_METHOD *method = nullptr;
    SSL_CTX *ctx = nullptr;

    OpenSSL_add_all_algorithms();       /* load & register all cryptos, etc. */
    SSL_load_error_strings();           /* load all error messages */
    method = ::TLSv1_2_server_method();   /* create new server-method instance */
    ctx = ::SSL_CTX_new(method);        /* create new context from method */
    
    if (ctx == NULL)
    {
        auto msg = fmt::format("::SSL_CTX_new failed: {}", ssl_helper::ossl_err_as_string());
        throw_krypto_ex(msg);
    }
    return ctx;
}

KRYPTO_INLINE 
void ssl_server::load_certificates(
        std::string const &certificate, 
        std::string const &key)
{
    /* set the local certificate from CertFile */
    if (::SSL_CTX_use_certificate_file(ctx, certificate.data(), SSL_FILETYPE_PEM) <= 0) 
    {
        auto msg = fmt::format("::SSL_CTX_use_certificate_file failed: {}", ssl_helper::ossl_err_as_string());
        throw_krypto_ex(msg);
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (::SSL_CTX_use_PrivateKey_file(ctx, key.data(), SSL_FILETYPE_PEM) <= 0) 
    {
        auto msg = fmt::format("::SSL_CTX_use_PrivateKey_file failed: {}", ssl_helper::ossl_err_as_string());
        throw_krypto_ex(msg);
    }
    /* verify private key */
    if (!::SSL_CTX_check_private_key(ctx))
    {
        throw_krypto_ex("Private key does not match the public certificate\n");
    }
}

} // namespace detail

using ssl_server = detail::ssl_server;

} // namespace krypto