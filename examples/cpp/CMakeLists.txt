cmake_minimum_required(VERSION 3.16)

find_package(Curses)

set(SRC_ECHO
    echo/main.cpp
    echo/policy.cpp
    echo/reply_selector.cpp
    echo/selector.cpp
    common/message_parser.cpp
)
if (NOT WIN32)
    list(APPEND SRC_ECHO echo/ncurses_helper.cpp)
endif()
add_executable(echo ${SRC_ECHO})
set_property(TARGET echo PROPERTY CXX_STANDARD 17)
target_include_directories(echo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(echo PRIVATE pan_cpp)
if (WIN32)
    target_precompile_headers(echo PRIVATE common/pch.hpp)
else()
    target_include_directories(echo PRIVATE ${CURSES_INCLUDE_DIR})
    target_link_libraries(echo PRIVATE ${CURSES_LIBRARIES})
endif()

set_target_properties(echo PROPERTIES PREFIX scion-)
install(TARGETS echo)

set(SRC_ECHO_ASYNC
    echo_async/main.cpp
    echo_async/args.cpp
    echo_async/proxy.cpp
    common/message_parser.cpp
)
add_executable(echo-async ${SRC_ECHO_ASYNC})
set_property(TARGET echo-async PROPERTY CXX_STANDARD 17)
target_include_directories(echo-async PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(echo-async PRIVATE pan_cpp)
if (WIN32)
    target_precompile_headers(echo-async REUSE_FROM echo)
endif()

set_target_properties(echo-async PROPERTIES PREFIX scion-)
install(TARGETS echo-async)
