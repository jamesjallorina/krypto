// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

#include "void_t.hpp"

#include <utility>

namespace krypto {
namespace support {

// Detection idiom for valid basic_handle
template <typename T, typename = void> 
struct is_basic_handle : std::false_type {};

template <typename T> 
struct is_basic_handle<T, void_t<typename T::handle_type, 
                                typename T::socket_type>> 
                                : std::true_type {};

} // namespace support
} // namespace kypto
