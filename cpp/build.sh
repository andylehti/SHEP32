#!/usr/bin/env bash
set -euo pipefail

scriptDir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
outDir="$scriptDir/bin"
outBin="$outDir/shep32-cpp"

mkdir -p "$outDir"

cxx="${CXX:-g++}"
cxxflags=( -std=c++17 -O2 )
ldflags=( -lcrypto -lz )

"$cxx" "${cxxflags[@]}" \
  "$scriptDir/shep32.cpp" \
  "$scriptDir/audit.cpp" \
  -o "$outBin" \
  "${ldflags[@]}"

echo "$outBin"
