// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include <krypto/detail/basic_handle.hpp>
#include <krypto/detail/ssl_helper.hpp>
#include <krypto/detail/tcp_server.hpp>

namespace krypto
{
namespace detail
{

/*
excerpt::


template <class Method> class ConnectionPolicy = TLSConnect>
class ssl_server;

template <template <class Method> class ConnectionPolicy>
class ssl_server
{
    // implementation here for server
}

*/

//references
// https://stackoverflow.com/questions/11705815/client-and-server-communication-using-ssl-c-c-ssl-protocol-dont-works
// http://simplestcodings.blogspot.com/2010/08/secure-server-client-using-openssl-in-c.html
class ssl_server
{

public:
    ssl_server() = delete;
    ssl_server(std::string const &certificate, std::string const &key);
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
    void run_listener(std::string const &port_number, const int no_of_connections);

private:
    void init_server_context(void);
    void load_certificate(
        std::string const &certificate, 
        std::string const &key);
    void cleanup_openssl()
    {
        EVP_cleanup();
    }

private:
    SSL_CTX *m_ctx = nullptr;
    std::unique_ptr<krypto::tcp_server> server = nullptr;
};

ssl_server::ssl_server(
    std::string const &certificate,
    std::string const &key
    )
{
    using krypto::tcp_server;
    server = std::make_unique<tcp_server>();
    try
    {
        init_server_context();
        load_certificate(certificate, key);
    }
    catch(const krypto_ex & ex)
    {
        throw;
    }
}

ssl_server::ssl_server(ssl_server && rhs) KRYPTO_NOEXCEPT
{
    if(this != &rhs)
    {
        m_ctx = std::move(rhs.m_ctx);
        server = std::move(rhs.server);
        rhs.m_ctx = nullptr;
    }
}

ssl_server &ssl_server::operator=(ssl_server && rhs) KRYPTO_NOEXCEPT
{
    if(this != &rhs)
    {
        m_ctx = std::move(rhs.m_ctx);
        server = std::move(rhs.server);
        rhs.m_ctx = nullptr;
    }
    return *this; 
}

ssl_server::~ssl_server()
{
    if(m_ctx)
        ::SSL_CTX_free(m_ctx);
    m_ctx = nullptr;
    cleanup_openssl();
}

KRYPTO_INLINE
void ssl_server::run_listener(std::string const &port_number, 
                                const int no_of_connections)
{
    server->create_listener(port_number, no_of_connections);
}

KRYPTO_INLINE
SSL *ssl_server::accept_connections()
{
    struct sockaddr_storage addr = {0};
    socklen_t len = 0;
    return accept_connections(addr,len);
}

KRYPTO_INLINE
SSL *ssl_server::accept_connections(
    struct sockaddr_storage &their_addr, 
    socklen_t &sin_size)
{
    SSL *ssl = nullptr;
    unique_socket client_socket;

    client_socket = make_unique_socket(server->accept_connections(their_addr, sin_size));

    ssl = ::SSL_new(m_ctx);
    ::SSL_set_fd(ssl, client_socket.release());
    return ssl;
}

KRYPTO_INLINE 
void ssl_server::init_server_context(void)
{
    const SSL_METHOD *method = nullptr;

    ::SSL_load_error_strings();           /* load all error messages */
    ::SSL_library_init();
    //::OpenSSL_add_all_algorithms();       /* load & register all cryptos, etc. */
    
    method = ::TLSv1_2_server_method();   /* create new server-method instance */
    m_ctx = ::SSL_CTX_new(method);        /* create new context from method */

    if(m_ctx == NULL)
    {
        auto msg = fmt::format("::SSL_CTX_new failed: {}", ssl_helper::ossl_err_as_string());
        throw_krypto_ex(msg);
    }
/*
    if (::SSL_CTX_set_cipher_list(m_ctx, CIPHER_LIST) <= 0) 
    {
        auto msg = fmt::format("::SSL_CTX_set_cipher_list failed {}", ossl_err_as_string());
        throw_krypto_ex(msg);
    }
*/
}

KRYPTO_INLINE 
void ssl_server::load_certificate(
        std::string const &certificate, 
        std::string const &key)
{
#if 0
    if (::SSL_CTX_load_verify_locations(m_ctx, certificate.data(), key.data()) != 1)
    {
        auto msg = fmt::format("::SSL_CTX_load_verify_locations failed: {}", ossl_err_as_string());
        throw_krypto_ex(msg);
    }
    if (::SSL_CTX_set_default_verify_paths(m_ctx) != 1)
    {
        auto msg = fmt::format("::SSL_CTX_set_default_verify_paths failed: {}", ossl_err_as_string());
        throw_krypto_ex(msg);
    }
#endif
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
#if 0
    ::SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    //::SSL_CTX_set_verify_depth(m_ctx, 4);
#endif
}

} // namespace detail

using ssl_server = detail::ssl_server;

} // namespace krypto