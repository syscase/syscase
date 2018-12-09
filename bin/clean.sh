#!/usr/bin/env bash

BASE_PATH=$(dirname "$(dirname "$(readlink -f "$0")")")

source "$BASE_PATH/bin/shared/strict-mode.sh"

BUILD_DIR="$BASE_PATH/build"

echo "Remove $BUILD_DIR"
rm -rf "$BUILD_DIR"
