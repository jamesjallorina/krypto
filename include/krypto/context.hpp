// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include "context_base.hpp"
#include "detail/ssl_helper.hpp"

namespace krypto {

class context : public context_base
{
public:
    explicit context(ssl_method m)
    {
        switch(m)
        {
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L) || defined(OPENSSL_NO_SSL2)
        case ssl_method::sslv2:
        case ssl_method::sslv2_client:
        case ssl_method::sslv2_server:
        {
            auto msg = fmt::format("SSLV2 is not supported in {}", OPENSSL_VERSION_NUMBER);
            throw_krypto_ex(msg);
        }
            break;
#else
        case ssl_method::sslv2:
            m_handle = ::SSL_CTX_new(::SSLv2_ssl_method());
            break;
            case ssl_method::sslv2_client:
            m_handle = ::SSL_CTX_new(::SSLv2_client_ssl_method());
            break;
            case ssl_method::sslv2_server:
            m_handle = ::SSL_CTX_new(::SSLv2_server_ssl_method());
            break;
#endif
#if defined(OPENSSL_NO_SSL3_METHOD)
            case ssl_method::sslv3:
            case ssl_method::sslv3_client:
            case ssl_method::sslv3_server:
            {
                auto msg = fmt::format("SSLV3 is not supported in {}", OPENSSL_VERSION_NUMBER);
                throw_krypto_ex(msg);
            }
                break;
#else
            case ssl_method::sslv3:
                m_handle = ::SSL_CTX_new(::SSLv3_ssl_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, SSL3_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, SSL3_VERSION);
                }
                break;
            case ssl_method::sslv3_client:
                m_handle = ::SSL_CTX_new(::SSLv3_client_ssl_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, SSL3_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, SSL3_VERSION);
                }
                break;
			case ssl_method::sslv3_server:
                m_handle = ::SSL_CTX_new(::SSLv3_server_ssl_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, SSL3_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, SSL3_VERSION);
                }
                break;
#endif
#if defined(OPENSSL_NO_TLS1_METHOD)
            case ssl_method::tlsv1:
            case ssl_method::tlsv1_client:
            case ssl_method::tlsv1_server:
            {
                auto msg = fmt::format("TLSV1 is not supported in {}", OPENSSL_VERSION_NUMBER);
                throw_krypto_ex(msg);
            }
                break;
#else
            case ssl_method::tlsv1:
                m_handle = ::SSL_CTX_new(::TLSv1_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_VERSION);
                }
                break;
            case ssl_method::tlsv1_client:
                m_handle = ::SSL_CTX_new(::TLSv1_client_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_VERSION);
                }
                break;
            case ssl_method::tlsv1_server:
                m_handle = ::SSL_CTX_new(::TLSv1_server_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_VERSION);
                }
                break;
#endif
            case ssl_method::sslv23:
                m_handle = ::SSL_CTX_new(::SSLv23_method());
                break;
            case ssl_method::sslv23_client:
                m_handle = ::SSL_CTX_new(::SSLv23_method());
                break;
            case ssl_method::sslv23_server:
                m_handle = ::SSL_CTX_new(::SSLv23_method());
                break;
#if defined(OPENSSL_NO_TLS1_1_METHOD)
            case ssl_method::tlsv11:
            case ssl_method::tlsv11_client:
            case ssl_method::tlsv11_server:
            {
                auto msg = fmt::format("TLSV11 is not supported in {}", OPENSSL_VERSION_NUMBER);
                throw_krypto_ex(msg);
            }
                break;
#else
            case ssl_method::tlsv11:
                m_handle = ::SSL_CTX_new(::TLSv1_1_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_1_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_1_VERSION);
                }
                break;
            case ssl_method::tlsv11_client:
                m_handle = ::SSL_CTX_new(::TLSv1_1_client_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_1_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_1_VERSION);
                }
                break;
            case ssl_method::tlsv11_server:
                m_handle = ::SSL_CTX_new(::TLSv1_1_server_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_1_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_1_VERSION);
                }
                break;
#endif
#if defined(OPENSSL_NO_TLS1_2_METHOD)
            case ssl_method::tlsv12:
            case ssl_method::tlsv12_client:
            case ssl_method::tlsv12_server:
            {
                auto msg = fmt::format("TLSV12 is not supported in {}", OPENSSL_VERSION_NUMBER);
                throw_krypto_ex(msg);
            }
                break;
    #else
            case ssl_method::tlsv12:
                m_handle = ::SSL_CTX_new(::TLSv1_2_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_2_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_2_VERSION);
                }
                break;
            case ssl_method::tlsv12_client:
                m_handle = ::SSL_CTX_new(::TLSv1_2_client_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_2_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_2_VERSION);
                }
                break;
            case ssl_method::tlsv12_server:
                m_handle = ::SSL_CTX_new(::TLSv1_2_server_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_2_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_2_VERSION);
                }
                break;
#endif
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
            case ssl_method::tlsv13:
                m_handle = ::SSL_CTX_new(::TLS_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_3_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_3_VERSION);
                }
                break;
            case ssl_method::tlsv13_client:
                m_handle = ::SSL_CTX_new(::TLS_client_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_3_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_3_VERSION);
                }
                break;
            case ssl_method::tlsv13_server:
                m_handle = ::SSL_CTX_new(::TLS_server_method());
                if(m_handle != nullptr)
                {
                    SSL_CTX_set_min_proto_version(m_handle, TLS1_3_VERSION);
                    SSL_CTX_set_max_proto_version(m_handle, TLS1_3_VERSION);
                }
                break;
#else
            case ssl_method::tlsv13:
            case ssl_method::tlsv13_client:
            case ssl_method::tlsv13_server:
            {
                auto msg = fmt::format("TLSV13 is not supported in {}", OPENSSL_VERSION_NUMBER);
                throw_krypto_ex(msg);
            }
                break;
#endif
            /// Any TLS version
            case ssl_method::tls:
                m_handle = ::SSL_CTX_new(::TLS_method());
                break;
            case ssl_method::tls_client:
                m_handle = ::SSL_CTX_new(::TLS_client_method());
                break;
            case ssl_method::tls_server:
                m_handle = ::SSL_CTX_new(::TLS_server_method());
                break;
            default:
            break;
        }

        if(m_handle == nullptr)
        {
            auto msg = fmt::format("{}", detail::ssl_helper::ossl_err_as_string());
            throw_krypto_ex(msg);
        }
    }

    ~context()
    {
        if(m_handle != nullptr)
        {
            ::SSL_CTX_free(m_handle);
        }
    }

    context(context const &) = delete;
    context& operator=(context const &) = delete;

    handle_type native_handle() { return m_handle; }

    bool is_valid() const
    {
        return (m_handle != nullptr);
    }

    /// @brief adds the options set via bit mask in options to ctx. 
    //	Options already set before are not cleared!
    long set_options(unsigned long options) const
    {
        return ::SSL_CTX_set_options(m_handle, options);
    }

    /// @brief clears the options set via bit mask in options to ctx.
    long clear_options(unsigned long options) const
    {
        return ::SSL_CTX_clear_options(m_handle, options);
    }

    /// @brief returns the options set for ctx.
    long get_options() const
    {
        return ::SSL_CTX_get_options(m_handle);
    }

    /// @brief adds the mode set via bit mask in mode to ctx. 
    //	Options already set before are not cleared. 
    long set_mode(long mode) const
    {
        return ::SSL_CTX_set_mode(m_handle, mode);
    }

    /// @brief SSL_CTX_clear_mode() removes the mode set via bit mask in mode from ctx.
    long clear_mode(long mode) const
    {
        return ::SSL_CTX_clear_mode(m_handle, mode);
    }

    /// @brief returns the mode set for ctx.
    long get_mode() const
    {
        return ::SSL_CTX_get_mode(m_handle);
    }
};

}	// namespace krypto
