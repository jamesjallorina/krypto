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
add_executable(test_ssl_server test_ssl_server.cpp)
TARGET_LINK_LIBRARIES(test_ssl_server -lm -lssl -lcrypto -g)

add_executable(test_ssl_client test_ssl_client.cpp)
TARGET_LINK_LIBRARIES(test_ssl_client -lm -lssl -lcrypto -g)

add_executable(test_ssl_server_raw test_ssl_server_raw.cpp)
TARGET_LINK_LIBRARIES(test_ssl_server_raw -lm -lssl -lcrypto -g)

add_executable(test_ssl_client_raw test_ssl_client_raw.cpp)
TARGET_LINK_LIBRARIES(test_ssl_client_raw -lm -lssl -lcrypto -g)

add_executable(test_scope_file_descriptor test_scope_file_descriptor.cpp)
TARGET_LINK_LIBRARIES(test_scope_file_descriptor -lm -lssl -lcrypto)

add_executable(test_scope_thread test_scope_thread.cpp)
TARGET_LINK_LIBRARIES(test_scope_thread -lpthread -lm -lssl -lcrypto)

add_executable(test_scope_thread_native_handle test_scope_thread_native_handle.cpp)
TARGET_LINK_LIBRARIES(test_scope_thread_native_handle -lpthread -lm -lssl -lcrypto)

add_executable(test_tcp_server test_tcp_server.cpp)
TARGET_LINK_LIBRARIES(test_tcp_server -lm -lssl -lcrypto)
add_executable(test_tcp_client test_tcp_client.cpp)
TARGET_LINK_LIBRARIES(test_tcp_client -lm -lssl -lcrypto)