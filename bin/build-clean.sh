#!/usr/bin/env bash

BASE_PATH=$(dirname "$(dirname "$(readlink -f "$0")")")

source "$BASE_PATH/bin/shared/strict-mode.sh"

BUILD_DIR="$BASE_PATH/build"

"$BASE_PATH/bin/clean.sh"
"$BASE_PATH/bin/build.sh"
