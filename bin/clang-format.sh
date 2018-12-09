#!/usr/bin/env bash

BASE_PATH=$(dirname "$(dirname "$(readlink -f "$0")")")

source "$BASE_PATH/bin/shared/strict-mode.sh"

cd "$BASE_PATH"

# fixstyle PATH PATTERN
function fixstyle {
  find "$BASE_PATH/$1" -iname "$2" | xargs clang-format -i
}

fixstyle src *.c
fixstyle include *.h
