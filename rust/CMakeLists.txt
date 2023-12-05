

#todo 'cargo test'

set( RUST_BINDINGS bindings.rs )

set(SOURCES
  build.rs
  Cargo.toml 
  src/lib.rs 
  wrapper.h
  ${CMAKE_SOURCE_DIR}/include/pan.h
  ${CMAKE_SOURCE_DIR}/cpp/go_handle.cpp
  ${CMAKE_SOURCE_DIR}/include/go_handle.hpp
 )


add_custom_target(pan-crate ALL DEPENDS  
pan pan_cpp
# ${RUST_BINDINGS}
)

add_custom_command(
    OUTPUT ${RUST_BINDINGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND cargo build
    DEPENDS ${SOURCES}
)

file(GLOB_RECURSE ACTUAL_BINDINGS
RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/target"

bindings.rs #apparently cmake cant match out/bindings.rs :(

)

#message(STATUS "actual-bindings: ${ACTUAL_BINDINGS}")

#list(GET ACTUAL_BINDINGS 1 TRUE_BINDINGS) # how to select the newest one of all the candidates here ??

#message(STATUS "${TRUE_BINDINGS}")

#get_filename_component(ABSOLUTE_BINDING "${TRUE_BINDINGS}"
#                       ABSOLUTE 
#                       BASE_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/target"                       
#                       )

#message(STATUS ${ABSOLUTE_BINDING}) 



#file(COPY_FILE  "${ABSOLUTE_BINDING}"
# "${CMAKE_CURRENT_SOURCE_DIR}/src/bindings.rs" )

# target_compile_definitions(pan-crate PRIVATE BUILDING_RUST )