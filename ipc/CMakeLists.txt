cmake_minimum_required(VERSION 3.16)
project(railroad_ipc LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(railroad_ipc ipc_demo.cpp)
target_compile_options(railroad_ipc PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(railroad_ipc PRIVATE rt)
