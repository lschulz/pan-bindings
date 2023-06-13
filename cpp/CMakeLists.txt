cmake_minimum_required(VERSION 3.16)


add_library(pan_cpp
    go_handle.cpp
    pan.cpp
)
set_property(TARGET pan_cpp PROPERTY CXX_STANDARD 17)
set_target_properties(pan_cpp PROPERTIES OUTPUT_NAME pancpp)
set_target_properties(pan_cpp PROPERTIES DEBUG_POSTFIX "d")
target_link_libraries(pan_cpp PUBLIC pan_c)
target_include_directories(pan_cpp PUBLIC "${CMAKE_SOURCE_DIR}/include")

set(PUBLIC_HEADERS
    "${CMAKE_SOURCE_DIR}/include/pan.hpp"
    "${CMAKE_SOURCE_DIR}/include/go_handle.hpp"
)
set_target_properties(pan_cpp PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")
set_target_properties(pan_cpp PROPERTIES VERSION "1.0.0")
set_target_properties(pan_cpp PROPERTIES SOVERSION "1")
install(TARGETS pan_cpp
    ARCHIVE
    LIBRARY
    PUBLIC_HEADER DESTINATION include/pan
)
