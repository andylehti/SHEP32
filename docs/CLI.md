# SHEP32 CLI notes

This repo now uses these public names:

- **SHEP32**: primary format
- **SHEP333**: extended format

Compatibility notes:

- The browser and HTML front end still export `window.SHEP32`.
- `--mode 0` means SHEP32.
- `--mode 1` means SHEP333.
- Some internal code still uses `333` as the extended derivation marker.
- Older docs and wrappers may still contain `SHEP64`, `SHEP72`, or generic `extended` wording.

## Unified key-input model

Use this model wherever the CLI supports key input:

- `--key`: explicit SHEP32 or SHEP333 key
- `--phrase`: explicit phrase, even if it looks like a key
- `--keyfile`: file containing an explicit key


Use `--text` for any numeric-looking input such as `0001`. Do not add a separate numeric key-generation flag, because that collapses distinct text inputs.

## Hidden advanced flags

These flags are still accepted for compatibility, but are hidden from regular help output:

- `--direct-bits`
- `--lane-bits`
- `--block-bytes`

## Current CLI surfaces

### Python package CLI

Uses subcommands such as:

- `key`
- `hash`
- `range`
- `bench`
- `pair`
- `enc`
- `dec`
- `pubkey`
- `sign`
- `verify`

### C++ native CLI

Uses a flat flag surface such as:

- `--text`
- `--file`
- `--encrypt`
- `--encrypt-file`
- `--decrypt`
- `--decrypt-file`
- `--pair`
- `--pubkey`
- `--sign`
- `--verify`
- `--bench`

### JavaScript / Node CLI runner

Also uses a flat flag surface through `js/shepCLI.js` and `SHEP32.runCli(...)`.

## Stability rule for the web UI

Do not rename the exported JavaScript object away from `SHEP32` unless the HTML pages are updated at the same time.
