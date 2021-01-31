# Copyright(c) 2021 krypto authors Distributed under the MIT License (http://opensource.org/licenses/MIT)

cmake_minimum_required(VERSION 3.10)

# set the project name
project(krypto_example CXX)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#find_path(KRYPTO_INCLUDE name "krypto.hpp" PATHS ../.. )
include_directories("../include/")

# add the executable
add_executable(test_scope_file_descriptor test_scope_file_descriptor.cpp)

add_executable(test_scope_thread test_scope_thread.cpp)
TARGET_LINK_LIBRARIES(test_scope_thread -lpthread)

add_executable(test_scope_thread_native_handle test_scope_thread_native_handle.cpp)
TARGET_LINK_LIBRARIES(test_scope_thread_native_handle -lpthread)