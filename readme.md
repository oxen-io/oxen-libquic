# libQUIC

C++ library for multi-stream QUIC implementations.

## Overview

"Bleeding-edge" is tracked in the dev branch, while the stable branch is intermittently updated as new features and capabilities are added.

## Building

### Requirements:

- Cmake
- C++ 17 compiler (Clang, GCC, etc)
- NGTCP2
- GNUTLS

### Building from Source

Clone the repository as usual, and run the following commands from the project source directory:

```
mkdir -p build
cd build
cmake .. -GNinja \
    -DCMAKE_C_COMPILER="clang" \
    -DCMAKE_CXX_COMPILER="clang++" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
    -DCMAKE_POLICY_DEFAULT_CMP0069=NEW
```

Building using clang/clang++ as the C/C++ compiler is not required; simply change to your compiler of choice. The same applies when compiling a release build, rather than a debug build.

### Unit Testing

All tests use [Catch2](https://github.com/catchorg/Catch2) as a formal unit-test framework. Tests are built by default as part of the standard Cmake build logic. The compiled and built test binaries can be found in `/build/tests/*`, named identically to their `*.cpp` source files (ex: `001-handshake.cpp` produces the binary `/build/tests/001`).
