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

The minimum Go version required for the Cgo wrapper itself is Go 1.17. As this
project depends on scion-apps you will need a Go version able to compile
scion-apps. Currently scion-apps supports Go version 1.19 and 1.20. The code
has been tested with Go version 1.20.9.

If you have an unsupported version of Go installed, you can download a separate
copy of Go and specify the path the to `go` binary in the CMake cache variable
`GO_BINARY` (defaults to `go`).

Building the C++ bindings requires Asio.

### Building
CMake is used as Makefile generator.

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
${CMAKE_INSTALL_PREFIX}/lib/libpan.a
${CMAKE_INSTALL_PREFIX}/lib/libpan.so
${CMAKE_INSTALL_PREFIX}/lib/libpancpp.so.1.0.0
${CMAKE_INSTALL_PREFIX}/lib/libpancpp.so.1
${CMAKE_INSTALL_PREFIX}/lib/libpancpp.so
${CMAKE_INSTALL_PREFIX}/include/pan/pan.hpp
${CMAKE_INSTALL_PREFIX}/include/pan/go_handle.hpp
${CMAKE_INSTALL_PREFIX}/bin/scion-echo
${CMAKE_INSTALL_PREFIX}/bin/scion-echo-async
```

The debug versions of the libraries have a `d` suffix and can be installed in
parallel to the release version.

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
