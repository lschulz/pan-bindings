cmake_minimum_required(VERSION 3.16)


set(SRC pan_wrapper.go)

if (WIN32)
    set(LIB lib)
    set(DLL dll)
else()
    set(LIB a)
    set(DLL so)
endif()

if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(OUTPUT_NAME libpand)
else()
    set(OUTPUT_NAME libpan)
endif()

set(HEADER ${OUTPUT_NAME}.h)
set(INCLUDE_HEADER "${CMAKE_SOURCE_DIR}/include/pan/pan.h")
set(CGO_HEADER_OUT "${CMAKE_CURRENT_BINARY_DIR}/${HEADER}")
set(STATIC_LIBRARY ${OUTPUT_NAME}.${LIB})
set(SHARED_LIBRARY ${OUTPUT_NAME}.${DLL})

add_custom_target(pan ALL DEPENDS ${STATIC_LIBRARY} ${INCLUDE_HEADER})
add_custom_command(
    OUTPUT ${STATIC_LIBRARY}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=1 ${GO_BINARY} build -buildmode=c-archive
        -o "${CMAKE_CURRENT_BINARY_DIR}/${STATIC_LIBRARY}" ${SRC}
    DEPENDS ${SRC}
)
add_custom_command(
    OUTPUT ${INCLUDE_HEADER}
    DEPENDS ${STATIC_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E copy "${CGO_HEADER_OUT}" "${INCLUDE_HEADER}"
)

install(FILES "${CGO_HEADER_OUT}" DESTINATION include/pan RENAME pan.h)
install(FILES "${CMAKE_SOURCE_DIR}/include/pan/pan_cdefs.h" DESTINATION include/pan)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${STATIC_LIBRARY}" TYPE LIB)

add_library(pan_c STATIC IMPORTED GLOBAL)
add_dependencies(pan_c pan)
set_target_properties(pan_c PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${STATIC_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/include)
if (WIN32)
    target_link_libraries(pan_c INTERFACE Ws2_32.lib)
endif()

if (${BUILD_SHARED_LIBS})
add_custom_target(cgo_pan_shared ALL DEPENDS ${SHARED_LIBRARY})
add_custom_command(
    OUTPUT ${SHARED_LIBRARY}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=1 ${GO_BINARY} build -buildmode=c-shared
        -o "${CMAKE_CURRENT_BINARY_DIR}/${SHARED_LIBRARY}" ${SRC}
    DEPENDS ${SRC}
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${SHARED_LIBRARY}" TYPE LIB RENAME "${SHARED_LIBRARY}")
endif(${BUILD_SHARED_LIBS})
