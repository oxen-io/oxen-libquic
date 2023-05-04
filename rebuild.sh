#!/bin/bash

# run this from root project directory

rm -rf build && \
mkdir build && \
cd build && \
cmake .. -GNinja \
    -DCMAKE_C_COMPILER="clang" \
    -DCMAKE_CXX_COMPILER="clang++" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
    -DWITH_LTO=OFF \
    -DCMAKE_POLICY_DEFAULT_CMP0069=NEW && \
ninja -v

