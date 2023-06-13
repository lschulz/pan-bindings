cmake_minimum_required(VERSION 3.16)

project(pan-bindings)


set(GO_BINARY "go" CACHE PATH "Path to go binary")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries")


add_subdirectory(go)
add_subdirectory(cpp)
add_subdirectory(examples/cpp)
