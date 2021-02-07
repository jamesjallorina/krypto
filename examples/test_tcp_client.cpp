// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorinana
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#include <krypto/krpyto.hpp>

#include <string>
#include <memory>
#include <iostream>

int main()
{
    using krypto::tcp_client;
    std::string port = "9000";
    std::string const &ip_addr = "localhost";

    std::unique_ptr<tcp_client> client = std::make_unique<tcp_client>();
    client->connect(ip_addr, port);
    
    assert(client->is_connected() == true);
    std::cout << "client connect status: " << client->is_connected() << std::endl;

    constexpr size_t buflen = 255;
    char message [buflen] = "this is a message from a client";
    std::cout << "sending a message to server: " << message << std::endl;

    client->send(message, buflen);

    client->recv(message, buflen);
    std::cout << "receiving echo from server: " << message << std::endl;

    return 0;
}