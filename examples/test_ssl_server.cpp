// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorinana
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#include <krypto/krpyto.hpp>

#include <memory>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>

void check_for_error(SSL *ssl, int result)
{
    if(result <= 0)
    {
        int result = ::SSL_get_error(ssl, result);
        std::cout << "errno: " << errno << std::endl;
        switch(result)
        {
            case SSL_ERROR_NONE:
            std::cout << "SSL_ERROR_NONE" << std::endl;
            break;
            case SSL_ERROR_ZERO_RETURN:
            std::cout << "SSL_ERROR_ZERO_RETURN" << std::endl;
            break;
            case SSL_ERROR_WANT_READ:
            std::cout << "SSL_ERROR_WANT_READ" << std::endl;
            break;
            case SSL_ERROR_WANT_WRITE:
            std::cout << "SSL_ERROR_WANT_WRITE" << std::endl;
            break;
            case SSL_ERROR_WANT_CONNECT:
            std::cout << "SSL_ERROR_WANT_CONNECT" << std::endl;
            break;
            case SSL_ERROR_WANT_X509_LOOKUP:
            std::cout << "SSL_ERROR_WANT_X509_LOOKUP" << std::endl;
            break;
            case SSL_ERROR_WANT_ASYNC:
            std::cout << "SSL_ERROR_WANT_ASYNC" << std::endl;
            break;
            case SSL_ERROR_WANT_ASYNC_JOB:
            std::cout << "SSL_ERROR_WANT_ASYNC_JOB" << std::endl;
            break;
            case SSL_ERROR_SYSCALL:
            std::cout << "SSL_ERROR_SYSCALL" << std::endl;
            break;
            case SSL_ERROR_SSL:
            std::cout << "SSL_ERROR_SSL" << std::endl;
            break;
            default:
            std::cout << "UNKNOWN_ERROR" << std::endl;
            break;
        }
    }
}

void response(std::unique_ptr<krypto::server_handle> handle) /* Serve the connection -- threadable */
{   
    int bytes;
    char buf[1024] = {0};
    char reply[1024] = {0};

    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

    std::cout << "process client requests . . ." << std::endl;
    std::cout << handle->get_certificates() << std::endl;             /* get any certificates */
    
    bytes = krypto::read(*handle, buf, sizeof(buf));    /* get request */

    check_for_error(handle->native_handle(), bytes);

    if ( bytes > 0 )
    {
        buf[bytes] = 0;
        std::cout << "client msg: " << buf << std::endl;
        sprintf(reply, HTMLecho, buf);      /* construct reply */
        krypto::write(*handle, reply, strlen(reply));   /* send reply */
    }
    else
        ERR_print_errors_fp(stderr);
}

int main(int argc, char **argv)
{
    using krypto::ssl_server;

    if (argc != 5)
    {
      std::cout << "Usage: test_ssl_server <port> <number_of_connections> <path_to_certificate> <path_to_key>\n";
      std::cout << "Example:\n";
      std::cout << "sudo test_ssl_server 15000 10 cacert.pem cakey.pem\n";
      return 1;
    }

    std::string const &port = argv[1];
    std::string const &number_of_connections = argv[2];
    std::string const &certificate = argv[3];
    std::string const &key = argv[4];
    std::unique_ptr<krypto::ssl_server> server;

    try
    {
        server = std::make_unique<ssl_server>(certificate, key);
        server->run_listener(port, std::stoi(number_of_connections));
    }
    catch(const krypto::krypto_ex & ex)
    {
        std::cerr << ex.what() << '\n';
    }
    std::cout << "server started . . ." << std::endl;

    while(true)
    {
        std::unique_ptr<krypto::server_handle> handle = 
            std::make_unique<krypto::server_handle> (
                                                    server->accept_connections()
                                                    );
        krypto::handshake(*handle);
        response(std::move(handle));
    }
    return 0;
}