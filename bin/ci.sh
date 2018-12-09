#!/usr/bin/env bash

BASE_PATH=$(dirname "$(dirname "$(readlink -f "$0")")")

source "$BASE_PATH/bin/shared/strict-mode.sh"

VERSION=2549b05dae4f309a575774b1b2e3e112d619fb84
EXPECTED_SHA512=b70813445f2a2754d50e0fe331ed425364bbc3397d3196ec19f396e2cd0d59c9cf159a5e9b17e7f01a7b80495209338a765d87bd8b4cc76ce9e0e277ce6aef00

SOURCE="https://raw.githubusercontent.com/Sarcasm/run-clang-format/$VERSION/run-clang-format.py"
RUN_CLANG_FORMAT="$BASE_PATH/bin/run-clang-format.py"
echo "$RUN_CLANG_FORMAT"

function download {
  wget --output-document="$RUN_CLANG_FORMAT" "$SOURCE"
  chmod +x "$RUN_CLANG_FORMAT"
}

function check_sha512 {
  sha512=$(sha512sum "$RUN_CLANG_FORMAT" | cut -d ' ' -f1)
  [[ "$sha512" == "$EXPECTED_SHA512" ]]
  return
}

if [ ! -f "$RUN_CLANG_FORMAT" ]; then
  download
fi

if ! check_sha512; then
  echo "run-clang-format.py out-of-date, updating..."
  download
  if ! check_sha512; then
    rm "$RUN_CLANG_FORMAT"
    >&2 echo "Could not download run-clang-format.py, sha512sum check failed"
    exit 1
  fi
  echo "run-clang-format.py successfully updated"
fi

"$RUN_CLANG_FORMAT" -r src include && "$BASE_PATH/bin/build-clean.sh"
