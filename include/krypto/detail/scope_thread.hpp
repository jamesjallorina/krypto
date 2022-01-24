// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include "../common.hpp"

#include <thread>

namespace krypto
{

namespace detail
{

template <class thread_type = std::thread>
class scoped_thread
{
public:
    using id_type = typename thread_type::id;
    using value_type = thread_type;
    using native_handle_type = typename thread_type::native_handle_type;

public:

    scoped_thread() KRYPTO_NOEXCEPT :
        m_thread_impl()
    {}

    template <class ...Args>
    scoped_thread(Args&&...args)
    {
        m_thread_impl = 
            thread_type(std::forward<Args>(args)...);
    }

    scoped_thread(scoped_thread && other) KRYPTO_NOEXCEPT
    {
        if(this != &other)
            m_thread_impl = std::move(other.m_thread_impl);        
    }

    scoped_thread &operator=(scoped_thread && other) KRYPTO_NOEXCEPT
    {
        if(this != &other)
            m_thread_impl = 
                std::move(other.m_thread_impl);
        return *this;
    }

    ~scoped_thread()
    {
        if(joinable())
            join();
    }

    bool joinable() const KRYPTO_NOEXCEPT
    {
        return m_thread_impl.joinable();
    }

    id_type get_id() const KRYPTO_NOEXCEPT
    {
        return m_thread_impl.get_id(); 
    }

    native_handle_type native_handle()
    {
        return m_thread_impl.native_handle(); 
    }

    static unsigned int hardware_concurrency() KRYPTO_NOEXCEPT
    {
        return thread_type::hardware_concurrency(); 
    }
    
    void join()
    {
        return m_thread_impl.join(); 
    }

    void detach()
    {
        return m_thread_impl.detach(); 
    }
    
    void swap( scoped_thread & other) KRYPTO_NOEXCEPT
    { 
        return m_thread_impl.swap(other.m_thread_impl);
    }

private:
    scoped_thread(scoped_thread const &) = delete;
    scoped_thread & operator=(scoped_thread const &) = delete;

private:
    thread_type m_thread_impl;
};

using unique_thread = scoped_thread<std::thread>;

}   // namespace detail
}   // namespace krypto
