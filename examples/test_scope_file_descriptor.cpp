// Copyright (c) 2021 cppnetwork
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#include <krypto/krpyto.hpp>

#include <sys/types.h>
#include <sys/socket.h>
#include <cassert>
#include <utility>
#include <iostream>

int main()
{
    using krypto::unique_socket;
    unique_socket u_socket;

    unique_socket u_socket_temp = socket(AF_INET, SOCK_STREAM, 0);

    // assert default constructor value
    assert(u_socket.native_handle() == -1);

    // assert non-trivial constructor
    assert(u_socket_temp.native_handle() != -1);

    // assert move constructor
    unique_socket u_socket_move = std::move(u_socket_temp);
    assert(u_socket_move.native_handle() != -1);
    assert(u_socket_temp.native_handle() == -1);

    // assert move copy operator
    u_socket = std::move(u_socket_move);
    assert(u_socket.native_handle() != -1);
    assert(u_socket_move.native_handle() == -1);
    
    // assert valid
    assert(u_socket.valid() == true);
    assert(u_socket_move.valid() == false);

    // assert bool operator
    if(u_socket)
        std::cout << "u_socket is valid" << std::endl;
    if(!u_socket_move)
        std::cout << "u_socket_move is not valid" << std::endl;

    std::cout << "Test Cases Passed!!!" << std::endl;
    return 0;
}