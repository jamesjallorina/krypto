// Copyright (c) 2021 cppnetwork
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#ifndef INCLUDE_KRYPTO_HPP
#define INCLUDE_KRYPTO_HPP

#include <krypto/detail/scope_file_descriptor.hpp>
#include <krypto/detail/scope_thread.hpp>

namespace krypto
{

using unique_socket = detail::scope_file_descriptor;
using unique_thread = detail::scoped_thread<std::thread>;

} // namespace krypto

#endif // INCLUDE_KRYPTO_HPP_