cmake_minimum_required(VERSION 3.16)
project(mtls_simulator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)

add_executable(mtls_simulator mtls_simulator.cpp)
target_link_libraries(mtls_simulator PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(mtls_simulator PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)