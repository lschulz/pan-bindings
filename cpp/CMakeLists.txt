cmake_minimum_required(VERSION 3.16)

add_library(pan_cpp
    go_handle.cpp
    pan.cpp
)
target_link_libraries(pan_cpp PRIVATE pan_c)
target_include_directories(pan_cpp PUBLIC "${CMAKE_SOURCE_DIR}/include")
set_target_properties(pan_cpp PROPERTIES
    CXX_STANDARD 17
    OUTPUT_NAME pancpp
    DEBUG_POSTFIX "d"
)
if (WIN32)
    target_link_libraries(pan_cpp INTERFACE Ws2_32.lib)
endif()

set(PUBLIC_HEADERS
    "${CMAKE_SOURCE_DIR}/include/pan/pan.hpp"
    "${CMAKE_SOURCE_DIR}/include/pan/go_handle.hpp"
)
set_target_properties(pan_cpp PROPERTIES
    PUBLIC_HEADER "${PUBLIC_HEADERS}"
    VERSION "1.1.0"
    SOVERSION "1"
)
install(TARGETS pan_cpp
    ARCHIVE
    LIBRARY
    PUBLIC_HEADER DESTINATION include/pan
)
