// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include "../common.hpp"
#include "../fmt/fmt.hpp"
#include "../support/is_basic_handle.hpp"
#include "scope_file_descriptor.hpp"

#include <type_traits>

namespace krypto {

namespace detail {

template<bool Serverhandle>
class basic_handle;

namespace ssl_helper
{

inline std::string ossl_err_as_string(void)
{ 
    BIO *bio = ::BIO_new (::BIO_s_mem ());
    ::ERR_print_errors (bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data (bio, &buf);
    char *ret = (char *) ::calloc (1, 1 + len);
    
    if (ret)
        ::memcpy (ret, buf, len);
    ::BIO_free (bio);
    std::string str(ret);
    free(ret);
    return str;
}

inline std::string certificates(SSL* ssl)
{
    std::string msg;
    X509 *cert = nullptr;
    char *line = nullptr;

    cert = ::SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        msg = fmt::format("Server certificates:\n");
        line = ::X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        msg += fmt::format("Subject: {}\n", std::string(line));
        ::free(line);
        line = ::X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        msg += fmt::format("Issuer: {}\n", std::string(line));
        ::free(line);
        ::X509_free(cert);
    }
    else
        msg = fmt::format("No certificates.\n");
    
    return msg;
}

template <typename HandleType, typename StreamBuf>
inline size_t write(HandleType &handle, StreamBuf *buf, size_t n_bytes)
{
    static_assert(support::is_basic_handle<HandleType>::value, "HandleType must meet the requirements");
    int write_result = 0;
    int ssl_io_result = 0;

    write_result = ::SSL_write(handle.native_handle(), buf, n_bytes);
    if(write_result <= 0)
    {
        ssl_io_result = ::SSL_get_error(handle.native_handle(), write_result);
        if(ssl_io_result <= SSL_ERROR_ZERO_RETURN)
        {
            if(ssl_io_result != SSL_ERROR_WANT_WRITE)
            {
                auto msg = fmt::format("::SSL_write failed: {}", ossl_err_as_string());
                throw_krypto_ex(msg);
            }
        }
    }
    return write_result;
}

template <typename HandleType, typename StreamBuf>
inline size_t read(HandleType &handle, StreamBuf *buf, size_t n_bytes)
{
    static_assert(support::is_basic_handle<HandleType>::value, "HandleType must meet the requirements");
    int recv_result = 0;
    int ssl_io_result = 0;

    recv_result = ::SSL_read(handle.native_handle(), buf, n_bytes);

    if(recv_result <= 0)
    {
        ssl_io_result = ::SSL_get_error(handle.native_handle(), recv_result);
        if(ssl_io_result <= SSL_ERROR_ZERO_RETURN)
        {
            if(ssl_io_result != SSL_ERROR_WANT_READ)
            {
                auto msg = fmt::format("::SSL_read failed: {}", ossl_err_as_string());
                throw_krypto_ex(msg);
            }
        }
    }
    return recv_result;
}

}   // namespace ssl_helper
}   // namespace detail

using detail::ssl_helper::write;
using detail::ssl_helper::read;

}   // namepsace krypto
