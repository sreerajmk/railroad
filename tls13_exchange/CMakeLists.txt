cmake_minimum_required(VERSION 3.16)
project(tls13_exchange LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)

add_executable(tls13_exchange tls13_exchange.cpp)
target_link_libraries(tls13_exchange PRIVATE OpenSSL::Crypto)
target_compile_options(tls13_exchange PRIVATE -Wall -Wextra -Wpedantic)
