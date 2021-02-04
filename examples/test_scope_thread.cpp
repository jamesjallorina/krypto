// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorinana
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#include <krypto/krpyto.hpp>

#include <cassert>
#include <iostream>
#include <chrono>
#include <thread>


// Note:
// example reference from: https://en.cppreference.com/w/cpp/thread/thread/thread

void worker_1(int n)
{
    for(int i = 0; i < 5; ++i)
    {
        std::cout << __FUNCTION__ << " executing" << std::endl;
        ++n;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void worker_2(int &n)
{
    for(int i = 0; i < 5; ++i)
    {
        std::cout << __FUNCTION__ << " executing" << std::endl;
        ++n;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

class o_worker_1
{
public:
    void run()
    {
        for(int i = 0; i < 5; ++i)
        {
            std::cout << __FUNCTION__ << " executing" << std::endl;
            ++n;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    int n = 0;

};

class o_worker_2
{
public:
    void operator()()
    {
        for(int i = 0; i < 5; ++i)
        {
            std::cout << __FUNCTION__ << " executing" << std::endl;
            ++n;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    int n = 0;
};

int main()
{
    using krypto::unique_thread;
    unique_thread u_thread_1;

    int n = 0;
    o_worker_1 o_worker_1;
    o_worker_2 o_worker_2;

    // test default constructor and joinable
    assert(u_thread_1.joinable() == false);


    // test user defined constructor
    unique_thread u_thread_2(worker_1, n + 1);
    assert(u_thread_2.joinable() == true);
    
    // test move copy constructor
    unique_thread u_thread_temp = std::move(u_thread_2);
    assert(u_thread_temp.joinable() == true);
    
    // test move assignment operator
    u_thread_2 = std::move(u_thread_temp);
    assert(u_thread_2.joinable() == true);

    u_thread_1 = unique_thread(worker_2, std::ref(n));

    // test thread get id
    unique_thread::id_type tid_1 = u_thread_1.get_id();
    unique_thread::id_type tid_2 = u_thread_2.get_id();
    assert(tid_1 == u_thread_1.get_id());
    assert(tid_2 == u_thread_2.get_id());
    assert(tid_1 != tid_2);

    // test hardward concurrency
    int supported_threads = std::thread::hardware_concurrency();    // since we use std::thread let's test it!
    assert(supported_threads == unique_thread::hardware_concurrency());
    
    // test swap
    u_thread_1.swap(u_thread_2);
    assert(tid_1 == u_thread_2.get_id());
    assert(tid_2 == u_thread_1.get_id());

    // test detach
    u_thread_1.detach();
    assert(u_thread_1.joinable() == false);

    return 0;
}