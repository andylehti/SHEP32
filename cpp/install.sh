#!/usr/bin/env bash
set -euo pipefail

scriptDir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
prefix="/usr/local"
binName="shep32-cpp"
aliasName="shep"
createAlias="auto"

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
      createAlias="yes"
      shift 2
      ;;
    --no-alias)
      createAlias="no"
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

builtBin="$scriptDir/bin/shep32-cpp"
if [[ ! -x "$builtBin" ]]; then
  "$scriptDir/build.sh" >/dev/null
fi

installDir="$prefix/bin"
mkdir -p "$installDir"
install -m 0755 "$builtBin" "$installDir/$binName"

echo "Installed: $installDir/$binName"

shouldAlias=0
if [[ "$createAlias" == "yes" ]]; then
  shouldAlias=1
elif [[ "$createAlias" == "auto" ]]; then
  if ! command -v "$aliasName" >/dev/null 2>&1; then
    shouldAlias=1
  fi
fi

if [[ $shouldAlias -eq 1 ]]; then
  ln -sf "$installDir/$binName" "$installDir/$aliasName"
  echo "Alias created: $installDir/$aliasName -> $installDir/$binName"
fi
