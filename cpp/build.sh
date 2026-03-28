#!/usr/bin/env bash
set -euo pipefail

scriptDir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
outDir="$scriptDir/bin"
outBin="$outDir/shep32-cpp"

mkdir -p "$outDir"

cxx="${CXX:-g++}"
cxxflags=( -std=c++17 -O2 )
ldflags=( -lcrypto -lz )

check_header() {
  local header="$1"
  if ! printf '#include <%s>\nint main(){return 0;}\n' "$header" | "$cxx" -std=c++17 -x c++ - -fsyntax-only >/dev/null 2>&1; then
    echo "Missing required C++ header: <$header>" >&2
    return 1
  fi
}

check_linker_flag() {
  local flag="$1"
  if ! printf 'int main(){return 0;}\n' | "$cxx" -std=c++17 -x c++ - -o /dev/null "$flag" >/dev/null 2>&1; then
    echo "Missing required linker dependency for flag: $flag" >&2
    return 1
  fi
}

check_header "boost/multiprecision/cpp_int.hpp"
check_header "openssl/sha.h"
check_header "zlib.h"
check_linker_flag "-lcrypto"
check_linker_flag "-lz"

"$cxx" "${cxxflags[@]}" \
  "$scriptDir/shep32.cpp" \
  "$scriptDir/audit.cpp" \
  -o "$outBin" \
  "${ldflags[@]}"

echo "$outBin"
