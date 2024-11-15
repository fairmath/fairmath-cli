#!/usr/bin/env bash

rm -rf BUILD
mkdir BUILD && cd BUILD
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
cd ../
