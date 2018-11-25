#!/usr/bin/env bash

BASE_PATH=$(dirname "$(readlink -f "$0")")

BUILD_DIR="$BASE_PATH/build"

echo "Create $BUILD_DIR"
mkdir -p "$BUILD_DIR"
echo "Setup $BUILD_DIR"
cd "$BUILD_DIR"
cmake ..
make
