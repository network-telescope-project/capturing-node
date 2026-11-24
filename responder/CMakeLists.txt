cmake_minimum_required(VERSION 3.16)
project(nt-responder CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(NT_STATIC "Link a fully static binary" OFF)

add_executable(nt-responder
    src/main.cpp
    src/engine.cpp
    src/packet.cpp
    src/pcap_io.cpp
    src/net.cpp
)
target_compile_options(nt-responder PRIVATE -Wall -Wextra -Wpedantic)
if(NT_STATIC)
    target_link_options(nt-responder PRIVATE -static)
endif()
