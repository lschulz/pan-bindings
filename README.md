SCION PAN Bindings for C, C++, and Python
=========================================

Language bindings for the PAN (Path Aware Networking) library of the SCION
Internet architecture project. The PAN library and other SCION demo applications
(in Go) can be found in the scion-apps repository:
https://github.com/netsec-ethz/scion-apps

More information on SCION: https://www.scion.org/

### Requirements
Most of the open-source implementation of SCION is written in Go. The bindings
in this repository use Cgo to export the Go functions to C. The exported C
functions can then be called from the C++ and Python wrappers. Therefore you
will need the Go compiler in addition to a C and C++ compiler. The Python
bindings require an installation of Python 3.

Since PAN depends on quic-go and quic-go only supports a narrow range of Go
versions with each release, your system-wide installation of Go might be too old
or too new to compile PAN. The current release of pan-bindings has been tested
with **Go 1.22.8**. If you have an unsupported version of Go installed, you can
download a separate copy of Go and specify the absolute path the to `go` binary
in the CMake cache variable `GO_BINARY` (defaults to `go`). Go itself can
install additional version, e.g.:
```bash
go install golang.org/dl/go1.22.8@latest
# Go will usually install the new go binary in `~/go/bin/`. Add this directrory
# to PATH or use the full path for the next command.
go1.22.8 download
# Run cmake with -D GO_BINARY=$(which go1.22.8)
```

Building the C++ bindings requires standalone (non-boost) Asio. The C++ examples
require ncurses on Linux.

### Building
CMake is used as Makefile generator.

#### Linux
Release:
```bash
mkdir -p build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_SHARED_LIBS=ON -B build/release
cmake --build build/release
```

Debug:
```bash
mkdir -p build/debug
cmake -D CMAKE_BUILD_TYPE=Debug -D BUILD_SHARED_LIBS=ON -B build/debug
cmake --build build/debug
```

Installation (by default to /usr/local):
```bash
sudo cmake --install build/release
sudo ldconfig
```
This will install the following files:
```
${CMAKE_INSTALL_PREFIX}/include/pan/pan.h
${CMAKE_INSTALL_PREFIX}/include/pan/pan_cdefs.h
${CMAKE_INSTALL_PREFIX}/lib/libpan.so.1.1.0
${CMAKE_INSTALL_PREFIX}/lib/libpan.so.1
${CMAKE_INSTALL_PREFIX}/lib/libpan.so
${CMAKE_INSTALL_PREFIX}/lib/libpancpp.so.1.1.0
${CMAKE_INSTALL_PREFIX}/lib/libpancpp.so.1
${CMAKE_INSTALL_PREFIX}/lib/libpancpp.so
${CMAKE_INSTALL_PREFIX}/include/pan/pan.hpp
${CMAKE_INSTALL_PREFIX}/include/pan/go_handle.hpp
${CMAKE_INSTALL_PREFIX}/bin/scion-echo
${CMAKE_INSTALL_PREFIX}/bin/scion-echo-async
```

The debug versions of the libraries have a `d` suffix and can be installed in
parallel to the release version.

#### Windows 10/11 (MSYS2 MinGW)
Install [MSYS2](https://www.msys2.org/) and Go. The following MSYS2 packets are
required:
```bash
pacman -Sy
pacman -S \
  mingw-w64-ucrt-x86_64-gcc   \
  mingw-w64-ucrt-x86_64-cmake \
  mingw-w64-ucrt-x86_64-ninja \
  mingw-w64-ucrt-x86_64-asio
```

Open an MSYS2 UCRT64 environment and navigate to the project root (Windows drive
letters are available as `/c` and so on).
```bash
mkdir build
cmake -D BUILD_SHARED_LIBS=ON -D GO_BINARY="$PROGRAMFILES/Go/bin/go.exe" -G 'Ninja Multi-Config' -B build
# Release:
cmake --build build --config Release
# Debug:
cmake --build build --config Debug
```

Headers and binaries can be installed as well:
```bash
cmake --install build --config Release --prefix /usr/local
```

### Doxygen Documentation
You can generate API documentation in `docs/gen` by running `doxygen` in the
project's root directory.

### Using the Bindings
For C:
- Include `pan/pan.h` and link with `-lpan`.

For C++:
- Include `pan/pan.hpp` and link with `-lpancpp`.

For Python:
- Make sure Python can find the contents of the `python` directory, e.g., by
  adding it to `PYTHONPATH` and import the module (`import pan`)

Example Applications
--------------------
The `examples` directory contains simple echo servers/clients demonstrating both
blocking and non-blocking IO.

Usage example (assuming the `tiny4.topo` topology from the SCION repository):
```bash
# Server
export SCION_DAEMON_ADDRESS=127.0.0.19:30255
scion-echo --local 127.0.0.1:51000       # blocking
scion-echo-async --local 127.0.0.1:51000 # non-blocking
# Client
export SCION_DAEMON_ADDRESS=127.0.0.27:30255
scion-echo --remote 1-ff00:0:111,127.0.0.1:51000       # blocking
scion-echo-async --remote 1-ff00:0:111,127.0.0.1:51000 # non-blocking
```

Python version:
```bash
# Server
export PYTHONPATH=${PWD}/python:${PYTHONPATH}
export SCION_DAEMON_ADDRESS=127.0.0.19:30255
examples/python/echo.py --local 127.0.0.1:51000         # blocking
examples/python/echo.py --async --local 127.0.0.1:51000 # non-blocking
# Client
export PYTHONPATH=${PWD}/python:${PYTHONPATH}
export SCION_DAEMON_ADDRESS=127.0.0.27:30255
examples/python/echo.py --remote 1-ff00:0:111,127.0.0.1:51000         # blocking
examples/python/echo.py --async --remote 1-ff00:0:111,127.0.0.1:51000 # non-blocking
```
