cmake_minimum_required(VERSION 3.16)


find_package(Curses REQUIRED)


add_executable(echo
    echo/main.cpp
    echo/policy.cpp
    echo/reply_selector.cpp
    echo/selector.cpp
    echo/ncurses_helper.cpp
    common/message_parser.cpp
)
set_property(TARGET echo PROPERTY CXX_STANDARD 17)
target_include_directories(echo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(echo PRIVATE pan_cpp)
target_include_directories(echo PRIVATE ${CURSES_INCLUDE_DIR})
target_link_libraries(echo PRIVATE ${CURSES_LIBRARIES})

set_target_properties(echo PROPERTIES PREFIX scion-)
install(TARGETS echo)

add_executable(echo-async
    echo_async/main.cpp
    common/message_parser.cpp
)
set_property(TARGET echo-async PROPERTY CXX_STANDARD 17)
target_include_directories(echo-async PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(echo-async PRIVATE pan_cpp)

set_target_properties(echo-async PROPERTIES PREFIX scion-)
install(TARGETS echo-async)
