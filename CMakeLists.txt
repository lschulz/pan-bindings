cmake_minimum_required(VERSION 3.16)

project(pan-bindings)


set(GO_BINARY "go" CACHE FILEPATH "Path to go binary")
option(BUILD_CPP "Build the C++ bindings" ON)
option(BUILD_EXAMPLES "Build the examples" ON)
option(BUILD_STATIC_LIBS "Build shared libraries" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)


add_subdirectory(go)

if (BUILD_CPP)
    add_subdirectory(cpp)
endif()

if (BUILD_EXAMPLES AND BUILD_CPP)
    add_subdirectory(examples/cpp)
endif()
