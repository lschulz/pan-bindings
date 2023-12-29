cmake_minimum_required(VERSION 3.16)

project(pan-bindings VERSION 1.0 )
set( PACKAGE_NAME "pan")

set(GO_BINARY "go" CACHE PATH "Path to go binary")
set(BUILD_CPP ON CACHE BOOL "Build the C++ bindings")
set(BUILD_RUST ON CACHE BOOL "Build the Rust bindings")
set(BUILD_EXAMPLES ON CACHE BOOL "Build the examples")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries")


add_subdirectory(go)

if (BUILD_CPP)
    add_subdirectory(cpp)
endif()

if (BUILD_EXAMPLES AND BUILD_CPP)
    add_subdirectory(examples/cpp)
endif()

#if(BUILD_RUST )
if(BUILD_RUST AND NOT CARGO_BUILD )
message(STATUS "BUILD RUST WITH CMAKE")
    add_subdirectory(rust)
endif()

if(BUILD_RUST AND CARGO_BUILD)
#copy rust recursively to install dir
message(STATTUS "current_src_dir: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATTUS "current_bin_dir: ${CMAKE_CURRENT_BINARY_DIR}")
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/rust DESTINATION .)
endif()

# if(BUILD_RUST AND BUILD_EXAMPLES )
if(BUILD_RUST AND BUILD_EXAMPLES AND NOT CARGO_BUILD)
    add_subdirectory(examples/rust)
endif()