cmake_minimum_required(VERSION 3.20)
project(syslog)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /DDEBUG /Zi /Od")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W3")

add_subdirectory(src/syslog)
add_subdirectory(src)
