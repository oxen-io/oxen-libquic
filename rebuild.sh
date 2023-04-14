#!/bin/bash

# run this from root project directory

rm -rf build && \
mkdir build && \
cd build && \
export CXX="$(which clang++)" && \
export C="$(which clang)" && \
cmake .. -GNinja -DCMAKE_C_COMPILER="clang" -DCMAKE_CXX_COMPILER="clang++" -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=1 && \
ninja
