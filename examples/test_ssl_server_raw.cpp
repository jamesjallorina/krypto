// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorinana
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#include <krypto/krpyto.hpp>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{
    SSL_load_error_strings();	
    SSL_library_init();
    //OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cacert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "cakey.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}

#include <iostream>
int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    /* Handle connections */
    printf("Handle connection\n");
    while(1) 
    {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
            printf("Succesful accept\n");
            int bytes = 0;
            char buf[1024] = {0};
            bytes = SSL_read(ssl, buf, sizeof(buf));

            printf("bytes received from read: %d", bytes);
            if(bytes <= 0)
            {
                int result = ::SSL_get_error(ssl, bytes);
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

            printf("Received from client: %s", buf);
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
