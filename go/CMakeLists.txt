cmake_minimum_required(VERSION 3.16)

set(SRC pan_wrapper.go)
set(HEADERS
    "${PROJECT_SOURCE_DIR}/include/pan/pan_cdefs.h"
)

if (WIN32)
    set(LIB lib)
else()
    set(LIB a)
endif()


# -N disables optimizations
# -l disables inlining
set(GCFLAGS_DEBUG -N -l)
set(CGO_BUILD_FLAGS_DEBUG -gcflags="${GCFLAGS_DEBUG}" -tags debug)

set(CGO_OUT_NAME cgo_out)
set(HEADER ${CGO_OUT_NAME}.h)
set(GENERATED_HEADER "${PROJECT_SOURCE_DIR}/include/pan/pan.h")
set(CGO_HEADER_OUT "${CMAKE_CURRENT_BINARY_DIR}/${HEADER}")
set(CGO_STATIC_LIBRARY ${CGO_OUT_NAME}.${LIB})

# Static library compiled from Go code
add_custom_target(pan_cgo ALL DEPENDS ${CGO_STATIC_LIBRARY} ${GENERATED_HEADER})
add_custom_command(
    OUTPUT ${CGO_STATIC_LIBRARY}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=1
         ${GO_BINARY} build "$<$<CONFIG:DEBUG>:${CGO_BUILD_FLAGS_DEBUG}>" -buildmode=c-archive
        -o "${CMAKE_CURRENT_BINARY_DIR}/${CGO_STATIC_LIBRARY}" ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND_EXPAND_LISTS
    DEPENDS ${SRC} ${HEADERS}
)
add_custom_command(
    OUTPUT ${GENERATED_HEADER}
    DEPENDS ${CGO_STATIC_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E copy "${CGO_HEADER_OUT}" "${GENERATED_HEADER}"
)

# Import result of Cgo compilation as library target
add_library(cgo_imported STATIC IMPORTED GLOBAL)
add_dependencies(cgo_imported pan_cgo)
set_target_properties(cgo_imported PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${CGO_STATIC_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/include
)

# Static library, linked with Cgo output
add_library(pan_c OBJECT
    "${PROJECT_SOURCE_DIR}/src/pan.c"
)
target_link_libraries(pan_c PUBLIC cgo_imported)
target_include_directories(pan_c PRIVATE "${PROJECT_SOURCE_DIR}/include")
if (WIN32)
    target_link_libraries(pan_c INTERFACE Ws2_32.lib)
endif()

install(FILES "${CGO_HEADER_OUT}" DESTINATION include/pan RENAME pan.h)
install(FILES "${PROJECT_SOURCE_DIR}/include/pan/pan_cdefs.h" DESTINATION include/pan)

# Build archive
if (${BUILD_STATIC_LIBS})
    add_library(pan_static STATIC)
    target_link_libraries(pan_static PUBLIC pan_c)
    set_target_properties(pan_static PROPERTIES
        OUTPUT_NAME pan
        DEBUG_POSTFIX "d"
    )
    install(TARGETS pan_static ARCHIVE)
endif(${BUILD_STATIC_LIBS})

# Link as shared library
if (${BUILD_SHARED_LIBS})
    add_library(pan_shared SHARED "$<TARGET_OBJECTS:pan_c>")
    add_dependencies(pan_shared pan_c)
    target_link_libraries(pan_shared PRIVATE
        "-Wl,--whole-archive $<TARGET_FILE:cgo_imported> -Wl,--no-whole-archive")
    target_include_directories(pan_shared INTERFACE ${PROJECT_SOURCE_DIR}/include)
    set_target_properties(pan_shared PROPERTIES
        OUTPUT_NAME pan
        DEBUG_POSTFIX "d"
        VERSION "1.1.1"
        SOVERSION "1"
    )
    if (WIN32)
        target_link_libraries(pan_shared PRIVATE Ws2_32.lib)
    endif()
    install(TARGETS pan_shared LIBRARY)
endif(${BUILD_SHARED_LIBS})
