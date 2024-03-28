# libQUIC

C++ library for multi-stream QUIC implementations.

## Overview

"Bleeding-edge" is tracked in the `dev` branch, while the `stable` branch is intermittently updated
as new features and capabilities are added that are suitable for production use.

## Building

### Requirements:

- CMake 3.13+
- C++17 compiler (such as clang >= 8 or GCC >= 8)
- gnutls (>= 3.7.2)
- libevent (>= 2.1)


### Building from Source

Clone the repository as usual, including submodules (either by passing `--recurse-submodules` to
`git clone`, or else running `git submodule update --init --recursive` the top-level project
directory).

To compile the library run the following commands from the project source directory:

```
mkdir -p build
cd build
cmake ..
make -j8  # Tweak as needed for the desired build parallelism
```

Various options can be added to the `cmake ..` line; some common options are:
- `-DCMAKE_BUILD_TYPE=Release` to make a release build
- `-DBUILD_STATIC_DEPS=ON` to build and bundle static versions of dependencies.
- `-DWITH_LTO=OFF` to disable link-time optimizations.
- `-DWARNINGS_AS_ERRORS=ON` to turn compiler warnings into fatal errors.
- `-DBUILD_TESTS=OFF` to disable building the test suite.
- `-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++` to use a specific compiler
- `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` to generate a `build/compile_commands.json` (used by various
  IDEs for detecting compilation settings and flags).
- `-GNinja` to use `ninja` for the build instead of `make`; this also requires changing the `make
  -j8` line to `ninja`.

## Testing

Unit tests use [Catch2](https://github.com/catchorg/Catch2) as a formal unit-test framework. Unit
tests are built by default as part of the standard CMake build logic (unless being built as a
subdirectory of another CMake project) and can be invoked through the `build/tests/alltests` binary.

Building the tests also build `./tests/speedtest-client` and `./tests/speedtest-server` which can be
used to test network performance of libquic streams.
