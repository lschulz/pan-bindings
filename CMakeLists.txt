cmake_minimum_required(VERSION 3.16)

project(pan-bindings)


set(GO_BINARY "go" CACHE PATH "Path to go binary")
set(BUILD_CPP ON CACHE BOOL "Build the C++ bindings")
set(BUILD_EXAMPLES ON CACHE BOOL "Build the examples")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries")


add_subdirectory(go)

if (BUILD_CPP)
    add_subdirectory(cpp)
endif()

if (BUILD_EXAMPLES AND BUILD_CPP)
    add_subdirectory(examples/cpp)
endif()
