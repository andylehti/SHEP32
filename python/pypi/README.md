# shep32

`shep32` packages the Python implementation of the SHEP32 and SHEP333 key and encryption tooling with both a Python API and a console CLI. It provides deterministic key generation, text and file encryption/decryption, detached output mode, Ed25519 public-key operations, range generation, benchmarking, and an interactive menu.

## What it includes

- SHEP32 key generation
- SHEP333 extended key generation
- Text and file encryption/decryption to `.sh32`
- Detached body/meta encryption mode
- Ed25519 public key derivation, signing, and verification
- Range generation and benchmark commands
- Interactive CLI mode

## Unified naming and CLI notes

- Use **SHEP32** for the primary format.
- Use **SHEP333** for the extended format.
- Use `--phrase` for phrases and `--key` for explicit keys.
- Advanced compatibility flags such as `--direct-bits`, `--lane-bits`, and `--block-bytes` are still accepted but are hidden from regular help output.

## Key formats

- **SHEP32** is the standard key format. It is a **32-byte** key, typically represented as a **64-character hexadecimal string**.
- **SHEP333** is the extended 333-bit key format. It uses the extended derivation path and produces the wider (72 character) mixed-alphabet (8 \[g-zA-Z\] characters) extended key equal to **333 bits**.

## Install from PyPI

```bash
pip install shep32
```

## CLI entry points

After installation, the main command is:

```bash
shep32 --help
```

Older builds may also expose `pyshep` as a compatibility alias.

Open the interactive menu:

```bash
shep32 start
```

## Common commands

Generate a fresh random key:

```bash
shep32 key
```

Generate a deterministic SHEP32 key from text:

```bash
shep32 hash --text "hello"
```

Generate a SHEP333 key:

```bash
shep32 hash --mode 1 --text "hello"
```

Generate a range:

```bash
shep32 range --start 0 --hashes 10
```

Encrypt text with an explicit SHEP32 key:

```bash
shep32 enc --text "secret" --key "9ab70f801ba94395af24ad2a5b1aedba3d428202bd6aa27a78c700bbe04707dd"
```

Encrypt text with an explicit SHEP333 key:

```bash
shep32 enc --text "secret" --key "<shep333-key>" --mode 1
```

Encrypt text with a passphrase in SHEP333 mode:

```bash
shep32 enc --text "secret" --phrase "1234" --mode 1
```


```bash
shep32 enc --text "secret" --phrase "1234" --mode 1
```

Encrypt a file:

```bash
shep32 enc --file ./notes.txt --phrase "password"
```

Decrypt a token file with a key file:

```bash
shep32 dec --file ./notes.sh32 --keyfile ./notes.pkey
```

Decrypt text with a passphrase in SHEP333 mode:

```bash
shep32 dec --text "<token>" --phrase "1234" --mode 1
```

Derive a public key:

```bash
shep32 pubkey --keyfile ./notes.pkey
```

Sign text:

```bash
shep32 sign --text "message" --keyfile ./notes.pkey
```

Verify a signature:

```bash
shep32 verify --text "message" --signature <signature> --public-key <publicKey>
```

Run a benchmark:

```bash
shep32 bench --hashes 10 --compare

# equal to both: 
# shep32 bench --hashes 10 --compare --input-bits 256
# shep32 bench --hashes 10 --compare --bits all
```

Use bits 1-256

```bash
shep32 bench --hashes 10 --compare --bits 1
```

## Key input rules for `enc`, `dec`, `pubkey`, and `sign`

- `--key` means an **explicit SHEP32 or SHEP333 key**
- `--phrase` means an **explicit phrase**, even if it looks like a valid key
- `--keyfile` means a file containing an **explicit SHEP32 or SHEP333 key**
- `--mode 0` selects **SHEP32** behavior
- `--mode 1` selects **SHEP333** behavior

Examples:

```bash
shep32 enc --text "secret" --key "<shep32-key>"
shep32 enc --text "secret" --key "<shep333-key>" --mode 1
shep32 enc --text "secret" --phrase "1234" --mode 1
shep32 dec --text "<token>" --key "<shep32-key>"
shep32 dec --text "<token>" --phrase "1234" --mode 1
```


## Python API

```python
from shep32 import generateKey, encryptData, decryptData, signData, verifySignature

key = generateKey("hello", mode = 0)
cipher, usedKey = encryptData("secret", key)
plain = decryptData(cipher, usedKey)

sig = signData("message", usedKey)
ok = verifySignature("message", sig["signature"], sig["publicKey"])
```

## CLI

The Python package installs the `shep32` command-line interface.

### Python API example

```python
from shep32 import generateKey, encryptData, decryptData, signData, verifySignature

key = generateKey("hello", 0)
cipher, usedKey = encryptData("secret", key)
plain = decryptData(cipher, usedKey)
sig = signData("message", usedKey)
ok = verifySignature("message", sig["signature"], sig["publicKey"])
```

## Python CLI commands

The Python CLI uses **subcommands**. The full set is:

- `start`
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

The top-level help menu is:

```text
usage: shep32 [-h] [--version] {start,key,hash,range,bench,pair,enc,dec,pubkey,sign,verify} ...

SHEP CLI — SHEP32 keys and SHEP333 extended keys

positional arguments:
  {start,key,hash,range,bench,pair,enc,dec,pubkey,sign,verify}
    start               Open the interactive menu
    key                 Generate a fresh random key or derive one from text, file, or phrase input
    hash                Deterministically derive a SHEP32 or SHEP333 key from text or file input
    range               Generate a range of SHEP32 or SHEP333 keys from a starting integer
    bench               Benchmark key generation speed and optional diffusion report
    pair                Show the two internal 256-bit encryption keys derived from a key or text/file source
    enc                 Encrypt text or a file into a .sh32 token
    dec                 Decrypt a .sh32 token, detached body/meta tokens, or a token file
    pubkey              Derive an Ed25519 public key from a SHEP key source
    sign                Sign text or file contents with the Ed25519 key derived from a SHEP key source
    verify              Verify text or file contents with a signature and public key

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

### `start`

Opens the interactive wizard/menu.

```bash
shep32 start
```

or simply:

```bash
shep32
```

### `key`

Generates a fresh random key, or derives one from text, file, or phrase input.

Examples:

```bash
shep32 key
shep32 key --text "hello"
shep32 key --file ./data.bin
shep32 key --phrase "passphrase"
shep32 key --mode 1 --text "hello"
```

Main options:

- `--text`, `--file`, `--phrase`: choose the key source
- numeric-looking inputs must still be passed with `--text` to preserve leading zeros
- `--mode 0|1`: SHEP32 or SHEP333
- `--save PATH`: write a `.pkey` file
- `--json`: emit structured output


### `hash`

Deterministically derives a key from exactly one source. Unlike `key`, this subcommand requires a source and is intended as the explicit deterministic route.

```bash
# SHEP32
shep32 hash --text "hello"
shep32 hash --mode 0 --file ./notes.txt

# SHEP333
shep32 hash --mode 1 --file ./notes.txt
shep32 hash --mode 1 --text "hello"
```

Main options:

- `--text TEXT`
- `--file PATH`
- `--mode 0|1`
- `--direct-bits N`
- `--lane-bits N`
- `--block-bytes N`
- `--json`

### `range`

Generates a sequence of SHEP32 or SHEP333 keys from a starting integer.

Examples:

```bash
shep32 range --start 0 --hashes 10
shep32 range --start 100 --hashes 50 --mode 1
shep32 range --start 0 --hashes 10 --bare
shep32 range --start 0 --hashes 10 --out hashes.txt
```

Main options:

- `--start INT`
- `--hashes INT`
- `--mode 0|1`
- `--bare`
- `--out PATH`
- `--progress`

### `bench`

Benchmarks key generation speed and can optionally run the compare or diffusion-report path.

Examples:

```bash
shep32 bench --hashes 1000
shep32 bench --hashes 1000 --compare
shep32 bench --hashes 1000 --input-bits 256 --compare
shep32 bench --hashes 1000 --no-progress
```


```bash
shep32 bench --hashes 10 --compare --bits 6
shep32 bench --hashes 10 --compare --bits all
```

Main options:

- `--hashes N`
- `--compare`
- `--input-bits N`
- `--mode 0|1`
- `--out PATH`
- `--no-progress`

Additional behavior notes:

- Some builds save the generated input/hash pairs automatically during benchmark runs.
- When present, the default saved file may use a parameter-based name such as `hashes{parameters}.txt`.
- In progress output such as `Diffusion report 18/514 (3%)`, the first number is a progress step, not necessarily a count of only-tested bits.

### `pair`

Shows the two internal encryption keys derived from a key or source.

Examples:

```bash
shep32 pair --text "hello"
shep32 pair --file ./notes.txt
shep32 pair --mode 1 --text "hello"
```

### `enc`

Encrypts text or a file into a `.sh32` token.

Examples:

```bash
shep32 enc --text "secret"
shep32 enc --text "secret" --key "<shep32-key>"
shep32 enc --text "secret" --key "<shep333-key>" --mode 1
shep32 enc --text "secret" --phrase "1234" --mode 1
shep32 enc --file ./notes.txt --keyfile ./notes.pkey
shep32 enc --file ./notes.txt --detached --out ./outdir
shep32 enc --stdin --keyfile ./notes.pkey
shep32 enc --stdin --delim PAYLOAD --keyfile ./notes.pkey
```

Main options:

- `--text TEXT`
- `--file PATH`
- `--stdin`
- `--delim NAME`
- `--key TEXT`
- `--phrase TEXT`
- `--keyfile PATH`
- `--mode 0|1`
- `--detached`
- `--no-compress`
- `--chunk-size N`
- `--chunk-bytes N`
- `--pow-bits N`
- `--pow-start N`
- `--out PATH`
- `--write-key PATH`
- `--quiet-key`
- `--no-limit`
- `--no-progress`
- `--json`


### `dec`

Decrypts a `.sh32` token, a detached body/meta pair, or a token file.

Examples:

```bash
shep32 dec --text "<token>" --key "<shep32-key>"
shep32 dec --text "<token>" --phrase "1234" --mode 1
shep32 dec --file ./notes.sh32 --keyfile ./notes.pkey
shep32 dec --body ./notes.body --meta ./notes.meta --keyfile ./notes.pkey
shep32 dec --text "<token>" --keyfile ./notes.pkey --as-text
```

Main options:

- `--text TEXT`
- `--file PATH`
- `--stdin`
- `--delim NAME`
- `--body TEXT_OR_PATH`
- `--meta TEXT_OR_PATH`
- `--key TEXT`
- `--phrase TEXT`
- `--keyfile PATH`
- `--mode 0|1`
- `--out PATH`
- `--as-text`
- `--no-progress`
- `--json`

### `pubkey`

Derives an Ed25519 public key from a key source.

Examples:

```bash
shep32 pubkey --key "<shep32-key>"
shep32 pubkey --key "<shep333-key>" --mode 1
shep32 pubkey --phrase "1234" --mode 1
shep32 pubkey --keyfile ./notes.pkey
```

### `sign`

Signs text or file contents.

Examples:

```bash
shep32 sign --text "message" --keyfile ./notes.pkey
shep32 sign --file ./message.txt --key "<shep32-key>"
shep32 sign --text "message" --phrase "1234" --mode 1
shep32 sign --stdin --keyfile ./notes.pkey
shep32 sign --stdin --delim PAYLOAD --keyfile ./notes.pkey
```

Output format:

```text
signature=<signature-token>
publicKey=<public-key-token>
```

### `verify`

Verifies text or file contents with a signature and public key.

Examples:

```bash
shep32 verify --text "message" --signature <signature> --public-key <publicKey>
shep32 verify --file ./message.txt --signature ./sig.txt --public-key ./pub.txt
shep32 verify --stdin --signature <signature> --public-key <publicKey>
```

Output format:

```text
true
```

or

```text
false
```

## Roundtrip Test

```bash
set -euo pipefail

TEXT="secret"
PHRASE="1234"
KEY32="43b5e6ddd9983bc6dc899f35ee32b2b2a8afe86bbcc814f67fbb8068225ad079"
KEY333="ucl70d48ap296075b9ef1dlbd6dfaf7043a5Bc267ebZd2cBaa6a05efaa2596dn1004b873"

echo "variables set"

ENC_PHRASE_0_RAW=$(shep32 enc --text "$TEXT" --phrase "$PHRASE" --mode 0 --no-progress)
echo "encryption 1"
ENC_PHRASE_1_RAW=$(shep32 enc --text "$TEXT" --phrase "$PHRASE" --mode 1 --no-progress)
echo "encryption 2"
ENC_KEY_0_RAW=$(shep32 enc --text "$TEXT" --key "$KEY32" --no-progress)
echo "encryption 3"
ENC_KEY_1_RAW=$(shep32 enc --text "$TEXT" --key "$KEY333" --mode 1 --no-progress)
echo "encryption 4"

ENC_PHRASE_0=$(printf '%s\n' "$ENC_PHRASE_0_RAW" | sed -n '1p')
ENC_PHRASE_1=$(printf '%s\n' "$ENC_PHRASE_1_RAW" | sed -n '1p')
ENC_KEY_0=$(printf '%s\n' "$ENC_KEY_0_RAW" | sed -n '1p')
ENC_KEY_1=$(printf '%s\n' "$ENC_KEY_1_RAW" | sed -n '1p')

DERIVED_PHRASE_0=$(printf '%s\n' "$ENC_PHRASE_0_RAW" | sed -n '2p')
DERIVED_PHRASE_1=$(printf '%s\n' "$ENC_PHRASE_1_RAW" | sed -n '2p')
DERIVED_KEY_0=$(printf '%s\n' "$ENC_KEY_0_RAW" | sed -n '2p')
DERIVED_KEY_1=$(printf '%s\n' "$ENC_KEY_1_RAW" | sed -n '2p')

DEC_PHRASE_0=$(shep32 dec --text "$ENC_PHRASE_0" --phrase "$PHRASE" --mode 0 --no-progress | tail -n 1)
echo "decryption 1"
DEC_PHRASE_1=$(shep32 dec --text "$ENC_PHRASE_1" --phrase "$PHRASE" --mode 1 --no-progress | tail -n 1)
echo "decryption 2"
DEC_KEY_0=$(shep32 dec --text "$ENC_KEY_0" --key "$KEY32" --no-progress | tail -n 1)
echo "decryption 3"
DEC_KEY_1=$(shep32 dec --text "$ENC_KEY_1" --key "$KEY333" --mode 1 --no-progress | tail -n 1)
echo "decryption 4"

echo "ENC_PHRASE_0=$ENC_PHRASE_0"
echo "DERIVED_PHRASE_0=$DERIVED_PHRASE_0"
echo "ENC_PHRASE_1=$ENC_PHRASE_1"
echo "DERIVED_PHRASE_1=$DERIVED_PHRASE_1"
echo "ENC_KEY_0=$ENC_KEY_0"
echo "DERIVED_KEY_0=$DERIVED_KEY_0"
echo "ENC_KEY_1=$ENC_KEY_1"
echo "DERIVED_KEY_1=$DERIVED_KEY_1"

[[ "$DEC_PHRASE_0" == "$TEXT" ]] && echo "PASS phrase mode 0" || { echo "FAIL phrase mode 0"; exit 1; }
[[ "$DEC_PHRASE_1" == "$TEXT" ]] && echo "PASS phrase mode 1" || { echo "FAIL phrase mode 1"; exit 1; }
[[ "$DEC_KEY_0" == "$TEXT" ]] && echo "PASS key mode 0" || { echo "FAIL key mode 0"; exit 1; }
[[ "$DEC_KEY_1" == "$TEXT" ]] && echo "PASS key mode 1" || { echo "FAIL key mode 1"; exit 1; }
```

## License

MIT License: [https://github.com/andylehti/SHEP32/blob/main/LICENSE](https://github.com/andylehti/SHEP32/blob/main/LICENSE)
