// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorinana
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#include <krypto/krpyto.hpp>

#include <string>
#include <memory>
#include <iostream>
#include <sys/socket.h>

int main()
{
    using krypto::tcp_server;
    using krypto::unique_socket;
    using krypto::make_unique_socket;
    std::string const &port = "9000";
    constexpr int number_of_connections = 1;
    unique_socket u_client_socket;

    std::unique_ptr<tcp_server> server = std::make_unique<tcp_server>();
    server->create_listener(port, number_of_connections);

    assert(server->is_listening() == true);
    std::cout << "server listen status: " << server->is_listening() << std::endl;
    
    while(true)
    {
        struct sockaddr_storage client_address = {0};
        socklen_t client_address_len = 0;
        char s[INET6_ADDRSTRLEN] = {0};

        u_client_socket = make_unique_socket(
                                        server->accept_connections(client_address, client_address_len)
                                        );

        if(!u_client_socket)
        {
            perror("::accept ");
            continue;
        }

        ::inet_ntop(client_address.ss_family, (struct sockaddr *)&client_address, s, sizeof s);
		std::cout << "server: got connection from " << s << std::endl;

        break;
    }

    constexpr size_t buflen = 255;
    char message[buflen] = {0};
    krypto::detail::socket_helper::recv(u_client_socket, message, buflen);

    std::cout << "receive msg from client: " << message << std::endl;

    std::cout << "echo msg to client: " << message << std::endl;
    krypto::detail::socket_helper::send(u_client_socket, message, buflen);

    return 0;
}