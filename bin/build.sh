#!/usr/bin/env bash

BASE_PATH=$(dirname "$(dirname "$(readlink -f "$0")")")

source "$BASE_PATH/bin/shared/strict-mode.sh"

BUILD_DIR="$BASE_PATH/build"

echo "Create $BUILD_DIR"
mkdir -p "$BUILD_DIR"
echo "Setup $BUILD_DIR"
cd "$BUILD_DIR"
cmake ..
make
