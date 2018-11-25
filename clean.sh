#!/usr/bin/env bash

BASE_PATH=$(dirname "$(readlink -f "$0")")

BUILD_DIR="$BASE_PATH/build"

echo "Remove $BUILD_DIR"
rm -rf "$BUILD_DIR"
"$BASE_PATH/build.sh"
