
set( RUST_EXAMPLES async_echo
                   async_socket_echo_unix
                   async_socket_echo_unix )

set(SOURCES
  build.rs
  Cargo.toml   
  src/async_echo.rs
  src/async_socket_echo_unix.rs
  src/async_socket_echo.rs
  main.rs
 )


add_custom_target(pan-rust-examples ALL DEPENDS  
pan pan_cpp pan-crate
# ${RUST_BINDINGS}
)

add_custom_command(
    OUTPUT ${RUST_EXAMPLES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND cargo build # --release -vv
    DEPENDS ${SOURCES}
)
