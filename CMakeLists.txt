cmake_minimum_required(VERSION 3.16)
project(cryptopals)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(set_1 set_1/set_1.cpp)
target_link_libraries(set_1 OpenSSL::Crypto)