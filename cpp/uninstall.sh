#!/usr/bin/env bash
set -euo pipefail

prefix="/usr/local"
binName="shep32-cpp"
aliasName="shep"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      prefix="$2"
      shift 2
      ;;
    --bin-name)
      binName="$2"
      shift 2
      ;;
    --alias)
      aliasName="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

installDir="$prefix/bin"
rm -f "$installDir/$binName"
if [[ -L "$installDir/$aliasName" ]]; then
  target="$(readlink "$installDir/$aliasName")"
  if [[ "$target" == "$installDir/$binName" || "$target" == *"/$binName" ]]; then
    rm -f "$installDir/$aliasName"
  fi
fi
