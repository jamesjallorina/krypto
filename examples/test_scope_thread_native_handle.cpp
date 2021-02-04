// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorinana
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#include <krypto/krpyto.hpp>

#include <iostream>
#include <mutex>
#include <cstring>
#include <pthread.h>

// Note:
// + example reference from: https://en.cppreference.com/w/cpp/thread/thread/native_handle
// + To test this binary must be run as root 

std::mutex iomutex;
void worker_schedule(int num)
{
    std::this_thread::sleep_for(std::chrono::seconds(1));
 
    sched_param sch;
    int policy; 
    pthread_getschedparam(pthread_self(), &policy, &sch);
    std::lock_guard<std::mutex> lk(iomutex);
    std::cout << "Thread " << num << " is executing at priority "
              << sch.sched_priority << '\n';
}

int main()
{
    using krypto::unique_thread;
    // test native handle
    unique_thread scheduler_thread_1(worker_schedule, 1);
    unique_thread scheduler_thread_2(worker_schedule , 2);

    unique_thread::native_handle_type native_handle_1 = scheduler_thread_1.native_handle();
    unique_thread::native_handle_type native_handle_2 = scheduler_thread_1.native_handle();

    sched_param sch;
    int policy;
    pthread_getschedparam(native_handle_1, &policy, &sch);
    sch.sched_priority = 20;
    if (pthread_setschedparam(native_handle_1, SCHED_FIFO, &sch))
    {
        std::cout << "Failed to setschedparam: " << std::strerror(errno) << '\n';
    }
}