// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorinana
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#include <krypto/krpyto.hpp>

#include <memory>
#include <iostream>
#include <stdio.h>
#include <unistd.h>


#include <typeinfo>
void send_request(std::unique_ptr<krypto::client_handle> handle)
{
    int bytes = 0;
    char buf[1024] = {0};
    char *msg = "This is a message from a ssl client";

    std::cout << "Connected with " << ::SSL_get_cipher(handle->native_handle()) << " encryption\n";
         
    krypto::write(*handle, msg, strlen(msg));           /* encrypt & send message */
    bytes = krypto::read(*handle, buf, sizeof(buf));    /* get reply & decrypt */
    buf[bytes] = 0;
    std::cout << "server msg: " << buf << std::endl;
}

int main(int argc, char **argv)
{
    using krypto::ssl_client;
    using krypto::client_handle;

    if (argc != 5)
    {
      std::cout << "Usage: test_ssl_client <hostname> <port> <path_to_certificate> <path_to_key>\n";
      std::cout << "Example:\n";
      std::cout << "test_ssl_server 127.0.0.1 15000 cacert.pem cakey.pem\n";
      return 1;
    }

    std::string const &hostname = argv[1];
    std::string const &port = argv[2];
    std::string const &certificate = argv[3];
    std::string const &key = argv[4];
    std::unique_ptr<ssl_client> client = nullptr;

    client = std::make_unique<ssl_client>(certificate, key);
    std::unique_ptr<client_handle> handle = 
                    std::make_unique<client_handle>(client->connect(hostname, port));

    krypto::handshake(*handle);
    std::cout << handle->get_certificates() << std::endl;
  
    send_request(std::move(handle));

    return 0;
}