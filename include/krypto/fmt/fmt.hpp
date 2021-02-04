// Copyright (c) 2021-present cppnetwork
// Copyright (c) 2021-present James Marjun Jallorina
// All Rights Reserved
//
// Distributed under the "MIT License". See the accompanying LICENSE.rst file.

#pragma once

// use header only fmt library
#if !defined(FMT_HEADER_ONLY)
#define FMT_HEADER_ONLY
#endif

// enable the 'n' flag in for backward compatibility with fmt 6.x
#define FMT_DEPRECATED_N_SPECIFIER
#include <krypto/fmt/bundled/core.h>
#include <krypto/fmt/bundled/format.h>