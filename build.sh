#!/usr/bin/env bash

rm -rf BUILD
mkdir BUILD && cd BUILD
cmake ..
cmake --build .
cd ../
