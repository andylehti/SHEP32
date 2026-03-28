# SHEP32

SHEP32 is a multi-language toolkit for deterministic key generation, authenticated encryption, signature generation, verification, file wrapping, range generation, and benchmark/audit work. The repository currently contains three front ends over the same general design:

- `python/` for the Python implementation and Python CLI
- `cpp/` for the native C++ implementation and native CLI
- `js/` for the standalone JavaScript module and Node/browser CLI-style runner

The codebase currently uses two names for the extended format. Older help or error text and parser descriptions may still say **extended** for **SHEP333**. The newer code path, internal mode value, and key derivation labels treat that extended format as **SHEP333**. In this README, **SHEP32** means the primary 32-byte format and **SHEP333** means the extended 333-bit format.

## What SHEP32 and SHEP333 are

### SHEP32

SHEP32 is the primary output format. It is a **32-byte** value, normally shown as a **64-character lowercase hexadecimal string**. In mode `0`, the code treats a valid 64-hex string as a direct key token. When the input is not already a 64-hex token, the code deterministically derives one from text, integers, or file bytes.

#### Example SHEP32 Keys

```
shep32 range --start 0 --hashes 10
```

```
0 = c245c2a9291fa37a8dc8c74feeabc1d03c09de371705c85d043a79568bf9fc91
1 = 43b5e6ddd9983bc6dc899f35ee32b2b2a8afe86bbcc814f67fbb8068225ad079
2 = 41902472cf371a16cd98117d473784fc6cb6d2e74d91c03b77a2bece6138cec3
3 = 1641e53ec94c8762306661dccfdf84a8badcb4db932f2b86c321e7d3cf772209
4 = 7393a6a8a0942e41ff63ec62cad6047336a6730cb253bad8e9b02f676ea74939
5 = 5ff9cad4a40c9acee33ce0fe9e952d27dc04bb5070aaba095c588042184187c9
6 = 98d2a120aa4502fda77d9a384d5b06f6f880d552c039d498c5c0426197e0eed5
7 = 9e033ee5f8980b8ec2287c3460aed517f34f5c534bd78b1d267ebea8ed1f1b63
8 = 1a733470dddc389daddd4714cbb5d9d67a3163278cb26ff3cbac793fdaf44e93
9 = 9faa4975b259e975592c44c8544725d945c21a87c66348620632d38beff7a591
```

### SHEP333

SHEP333 is the extended format. Internally, the extended path is keyed with mode value `333`, and the generator produces a wider transport string by starting from a 64-hex body and injecting eight auxiliary symbols from the extended alphabet across the final output. The current code still exposes this as `mode 1` in several CLIs, but the derivation and internal labeling treat it as the `333` path.

### How SHEP333 Works

SHEP333 is the extended key path. It begins by turning the input into raw bytes; it is processed through the selected byte stream and is wrapped with a sentinel byte and converted into a single large integer so the next stage works from one preserved numeric state.

That integer is then expanded by the wide trace pipeline into a structured internal state with multiple checkpoints. This stage repeatedly grows, packs/pads, permutes, and mixes the number so the final traced value is tied to both the original input and the way it was expanded. From that trace, the code derives a domain-separated root and uses it to generate a 64-hex body. That body is the base material for the extended key, but it is not the final output.

Next comes the lottery injection stage. The code runs eight rounds that choose both a position and an injected symbol. The position is chosen from the remaining open slots in the 72-character output, and the symbol is chosen from an auxiliary alphabet outside standard hex. Each round updates the running state, so later picks depend on the earlier ones. Once all eight rounds are complete, those injected symbols are placed into their selected positions and the 64 hex characters fill every remaining slot. That produces the first mixed 72-character form.

The process then rebounds from that first result. The code hashes together the root, the first assembled extended string, the serialized injection schedule, and part of the earlier trace to create a new seed. Using that rebound seed, it generates a second 64-hex body and runs a second eight-round lottery injection pass. The final SHEP333 key is produced by placing that second set of injected symbols into their chosen positions and filling the rest with the second body. The result is a 72-character extended key built from a 64-hex body plus 8 injected auxiliary symbols, generated through two body passes and two lottery passes tied back to the traced input state.

The result is an aesthetic key that is 77 bits larger than standard 256 bit hashes.

#### Example Extended SHEP333 Keys

```
shep32 range --mode 1 --hashes 10 --start 0
```

```
0 = 3b397f62Y4aad6b708c644c76H1459f68f5c36a50712A6IC41d6e151dQca2R921fm422ea
1 = ucl70d48ap296075b9ef1dlbd6dfaf7043a5Bc267ebZd2cBaa6a05efaa2596dn1004b873
2 = 86e03fa76bXl43ba191b8e58e0SDA3fc38685450c25Y377o67f6ff3c8071f229acedOd1b
3 = 7fbb8bc13bfd696fc44aa11D49aqb5eF7awdN585de24d277be0M1f4kf97b2Jb61239d1c7
4 = d8644542Oe722144863DVe89d8e6212db5Z796kd9d1cb10a580c8aa05aeVX4e9R970f043
5 = 296eIegd9f7dbafQqdf288f5754661951c4ebDf4c828Q7ee843e6700nafeY8026b4307ef
6 = a2JVc2e7o722Qc081gd1c9z3k7be930c1cbdcd7ebbeaf9a0c92375394d838671b40k9356
7 = 95fbc60see7f31c1c87cf7id5Ee1f453X5IZ7175i790fb4Ved6215d148207fef9074af02
8 = T992c74cc2afdM84d9a702ac5fGbc5ak9440437S337ap29776000e80079b9159dAC94f61
9 = d03f6b48s7656Y6fO7e12bt6f928100584f99367803db1b5Ucxec0c1cyc9c293x3fe3b1a
```

## What the code actually does

The project has two layers:

1. A **custom deterministic derivation layer** that turns input into a primary or extended SHEP key.
2. A **standard cryptographic payload layer** that uses those derived values to drive authenticated encryption and signatures.

This distinction matters. The code math determines the project-specific key format and internal subkeys. The actual payload encryption and integrity checks are performed with **XChaCha20-Poly1305**, and signature operations use **Ed25519**. In the Python implementation, XChaCha20-Poly1305 is built from `hChaCha20` plus `ChaCha20Poly1305`, and Ed25519 keys are derived from internal seed material labeled `PUBSEED`.

## How the key-generation math works

At a high level, the derivation path is built from these pieces:

### 1. Input normalization

Text input is encoded as UTF-16LE with a leading one-byte sentinel marker. File input is either used directly or wrapped into a file payload record before encryption. That sentinel is why the code can reliably reject malformed data with the `byte sentinel missing` error on decode.

### 2. Deterministic RNG and digit transforms

The code includes a deterministic MT19937-style generator and a large set of digit-based transforms: base conversion, radix shuffling, digit products, rotating digit windows, biased routing, bit redistribution, and fixed decimal-width slicing. These are used to move between integer, radix, and mixed-string representations in a deterministic way. The JavaScript and CPP ports both include the same major stages such as `processKey`, `distributeBits`, `decodeShift`, and related routing functions.

### 3. `fold64` and `computeBound`

A custom 64-bit mixing pipeline called `fold64` takes strings and expands them into a 256-bit hex output. That hex is then passed through `computeBound`, which remixes the result again and also derives a routing/base factor. This is the core compression and diffusion stage used repeatedly across key derivation, internal subkey derivation, authentication tags, and the extended-format schedule generation.

### 4. Primary SHEP32 generation

For smaller inputs, the code can take a more direct route. It sentinel-encodes the input, feeds it into the key-derivation path, and produces a 64-hex SHEP32 token. For larger inputs, it first diffuses the byte stream in blocks and then hashes the diffused result into the same 64-hex form.

### 5. Extended SHEP333 generation

The extended path builds a wide trace state, binds it through `fold64`, computes a 64-hex body, then injects eight auxiliary symbols at computed positions. That produces the extended transport form. The mode value used by the internal derivation code for this path is `333`, even where the CLI still presents it to the user as `mode 1` or “SHEP72.”

*See **How SHEP333 Works** Section.*

### 6. Internal subkeys

A single master key is not used directly for everything. The code derives labeled internal roots such as `ENC`, `AUTH`, `NONCE`, `VERIFY`, and `PUBSEED`, then uses those to derive per-message and per-chunk values. That is how encryption keys, authentication roots, nonces, verification tokens, and Ed25519 seeds are separated.

## How encryption works

When encrypting:

1. The input is normalized to bytes.
2. Compression is optionally applied with zlib/deflate.
3. The message is split into chunks.
4. A per-message seed expands into salt, nonce, and IV values.
5. Internal labeled roots derive the chunk encryption key, nonce root, verification root, and authentication root.
6. Each chunk is encrypted with **XChaCha20-Poly1305**.
7. The encrypted chunks are packed into a portable text form.
8. A verification token and authentication tag are computed over metadata plus body.
9. Optional proof-of-work can be added.
10. Output is written either as a single envelope or as detached `meta` plus `body`.

When decrypting, the reverse path checks the verification token, checks the authentication tag, verifies optional proof-of-work, decrypts each chunk, optionally inflates compressed data, and then restores the original text or file payload.

## Repository layout

```text
SHEP32-main/
├── README.md
├── LICENSE
├── python/
│   ├── shep32.py
│   ├── shep32cli.py
│   └── app.py
├── cpp/
│   ├── shep32.cpp
│   ├── audit.cpp
│   ├── audit.h
│   ├── build.sh
│   ├── install.sh
│   └── ...
├── js/
│   ├── shep32.js
│   └── shepCLI.js
├── analyses/
├── audit/
└── offline GUI/
```
## Install and use the Python version

### Option A: install from this repo into an environment

1. Clone the repository and enter the Python package directory
2. Create and activate a virtual environment
3. Install the package in editable mode
4. After installation, the Python CLI is available in that environment

```bash
# Step 1:
git clone https://github.com/andylehti/SHEP32.git
cd SHEP32/python
# Step 2:
python3 -m venv .venv
source .venv/bin/activate
# Step 3:
pip install -e .
# Step 4:
shep32 --help
```

### Option B: install from PyPI

```bash
pip install shep32
```

Depending on the published build, the CLI may be exposed as `shep32`, `pyshep`, or both.

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

### `start`

Opens the interactive wizard/menu.

```bash
shep32 start
```

or

```bash
shep32
```

### `key`

Generates a fresh random key, or derives one from text, integer, file, or phrase input.

Examples:

```bash
shep32 key
shep32 key --text "hello"
shep32 key --value 12345
shep32 key --file ./data.bin
shep32 key --phrase "passphrase"
shep32 key --mode 1 --text "1234"
shep32 key --phrase "1234" --mode 1
```

Main options:

- `--text`, `--value`, `--file`, `--phrase`: [choose the source]
- `--mode 0|1`: [SHEP32 vs SHEP333]
- `--save PATH`: [write a] `.pkey` [file]

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

### `range`

Generates keys over a sequential integer range.

```bash
shep32 range --start 0 --hashes 10
shep32 range --start 1000 --hashes 500 --out hashes.txt --bare
```

Main options:

- `--start`: first integer
- `--hashes`: number of outputs
- `--out`: write to file
- `--bare`: write only the hash values
- `--progress`: show progress

### `bench`

Benchmarks key generation speed and optional diffusion comparison.

```bash
shep32 bench --hashes 10 --compare
shep32 bench --hashes 10 --compare --bits 6
shep32 bench --hashes 10 --compare --bits all
```

More options

- `--hashes`: number of test inputs
- `--start`: starting value for sequential mode
- `--random-inputs` / `--sequential`: choose random or sequential inputs
- `--input-bits`: width of random inputs
- `--compare`: include diffusion comparison data
- `--bits`: number of compared input bits, or `all`
- `--out`: write report
- `--no-progress`: disable progress output

### `pair`

Shows the two internal 256-bit keys derived from a source. This is useful for inspecting the split internal key material produced from a SHEP32 or SHEP333 master source.

```bash
shep32 pair --mode 0 --text "hello"
shep32 pair --mode 1 --text "hello"
```

### `enc`

Encrypts text or a file into a `.sh32` token or detached `body`/`meta` pair.

```bash
shep32 enc --text "secret" --phrase "password"
shep32 enc --text "secret" --key "43b5e6ddd9983bc6dc899f35ee32b2b2a8afe86bbcc814f67fbb8068225ad079"
shep32 enc --text "secret" --key "ucl70d48ap296075b9ef1dlbd6dfaf7043a5Bc267ebZd2cBaa6a05efaa2596dn1004b873" --mode 1
shep32 enc --text "secret" --phrase "1234" --mode 1
shep32 enc --file ./notes.txt --keyfile ./notes.pkey
shep32 enc --text "secret" --phrase "password" --detached
```

Main options:

- `--text`, `--file`, `--stdin`: input source
- `--key`, `--phrase`, `--keyfile`: encryption key source
- `--mode 0|1`: SHEP32 or SHEP333 mode
- `--detached`: write separate body and meta output
- `--no-compress`: disable zlib compression
- `--chunk-size`, `--chunk-bytes`: chunk geometry
- `--pow-bits`, `--pow-start`: proof-of-work
- `--out`: output path
- `--no-limit`: override file-size limit
- `--quiet-key`: suppress printing the derived key
- `--write-key`: write a key file
- `--json`: JSON output

### `dec`

Decrypts a single token, a token file, or a detached body/meta pair.

```bash
shep32 dec --text "TOKEN" --phrase "password"
shep32 dec --file ./notes.sh32 --keyfile ./notes.pkey
shep32 dec --body ./notes.body --meta ./notes.meta --keyfile ./notes.pkey
```

Main options:

- `--text`, `--file`, `--stdin`: token source
- `--body`, `--meta`: detached input pair
- `--key`, `--phrase`, `--keyfile`: decryption key source
- `--mode`: `0`, `1`, or blank for auto-detect
- `--out`: write plaintext or restored file
- `--as-text`: force text output even if the payload is a wrapped file
- `--no-progress`: suppress progress
- `--json`: JSON output

### `pubkey`

Derives the Ed25519 public key associated with a SHEP key source.

```bash
shep32 pubkey --keyfile ./notes.pkey
```

### `sign`

Signs text or file contents with the Ed25519 key derived from the SHEP key source.

```bash
shep32 sign --text "message" --keyfile ./notes.pkey
```

### `verify`

Verifies text or file contents against a signature and public key.

```bash
shep32 verify --text "message" --signature <signature> --public-key <publicKey>
```

## Install and use the JavaScript version

There is no npm package in this repository. The JavaScript implementation is shipped as standalone files in `js/`.

### Node.js CLI-style usage

From the repository root:

```bash
node js/shepCLI.js --help
```

Examples:

```bash
node js/shepCLI.js --text "hello"
node js/shepCLI.js --mode 1 --text "hello"
node js/shepCLI.js --encrypt "secret" --key password
node js/shepCLI.js --decrypt TOKEN --key KEY
node js/shepCLI.js --pair --text "hello"
node js/shepCLI.js --pubkey --key password
node js/shepCLI.js --sign "message" --key password
node js/shepCLI.js --verify "message" --signature <signature> --public-key <publicKey>
node js/shepCLI.js --start 0 --hashes 10
node js/shepCLI.js --bench 1000
```

### Browser usage

Include the standalone module:

```html
<script src="./js/shep32.js"></script>
```

Then call the browser command runner:

```html
<script>
(async () => {
  const res = await SHEP32.runCli('--text "hello"')
  console.log(res.stdout)
})()
</script>
```

The browser runner supports the same command-style surface, but file operations use an **in-memory file map** rather than direct disk access.

### JavaScript / Node CLI commands

The JavaScript CLI uses **flat flags** instead of Python subcommands. The important actions are:

- `--text`, `--value`, `--file`: generate a key from source input
- `--start ... --hashes ...`: range mode
- `--bench N`: benchmark mode
- `--pair`: show internal key pair
- `--pubkey`: derive public key
- `--sign`: sign input
- `--verify`: verify input
- `--encrypt` / `--encrypt-file`: encrypt text or file
- `--decrypt` / `--decrypt-file`: decrypt token or token file
- `--body` + `--meta`: detached decrypt path

Important shared flags include:

- `--mode`: `0` for SHEP32 primary, `1` for the extended path
- `--chunk-size`, `--chunk-bytes`: chunking control
- `--detached`: detached output
- `--no-compress`: disable compression
- `--pow-bits`, `--pow-start`: proof-of-work
- `--as-text`: force text output on decrypt
- `--quiet-key`: suppress printed key
- `--write-key`: write a key file
- `--stdin`, `--delim`: standard-input input path
- `--out`: write output to file
- `--bare`: bare hash output in range mode
- `--compare`, `--deep-audit`, `--top-count`, `--audit-dir`: benchmark and audit flags in the native CLI surface; the JS version exposes benchmarking but may not ship every native reporting path the same way in every build.

## Install and use the C++ version

The native build lives in `cpp/`.

### Build

```bash
cd cpp
./build.sh
```

### Install

System install:

```bash
cd cpp
sudo ./install.sh
```

User-local install:

```bash
cd cpp
./install.sh --prefix "$HOME/.local"
```

Recommended binary name:

```bash
shep32-cpp
```

An optional `shep` alias may also be installed if that command is not already present in `PATH`.

### Native C++ CLI behavior

- Running `shep32-cpp` or `shep` (if command is not present in `PATH`) with **no arguments** opens the interactive menu.
- Running it with flags uses the flat CLI.

Examples:

```bash
shep32-cpp --help
shep32-cpp --text "hello"
shep32-cpp --mode 1 --text "hello"
shep32-cpp --encrypt "secret" --key password
shep32-cpp --encrypt-file ./notes.txt --keyfile ./notes.pkey
shep32-cpp --decrypt-file ./notes.sh32 --keyfile ./notes.pkey
shep32-cpp --pair --text "hello"
shep32-cpp --pubkey --keyfile ./notes.pkey
shep32-cpp --sign "message" --keyfile ./notes.pkey
shep32-cpp --verify "message" --signature <signature> --public-key <publicKey>
shep32-cpp --start 0 --hashes 10
shep32-cpp --bench 1000 --compare
```

The flat command set matches the help text in `cpp/shep32.cpp`: hash input by `--text` / `--value` / `--file`, encryption/decryption flags, detached mode, signing, verification, internal pair inspection, range generation, and benchmark/audit flags.

## Common concepts across all versions

### Key sources

A command may accept:

- raw text
- an integer
- a file
- a passphrase
- a direct key token
- a `.pkey` file

### Wrapped files

When you encrypt a file, the code does not just dump the bytes raw into the transport token. It wraps the file name and file bytes into a structured file payload first, then encrypts that payload. On decrypt, the code can restore the original file name and data unless `--as-text` is used.

### Detached mode

Detached mode writes encryption output as separate **body** and **meta** components rather than as a single envelope. Both are required for decryption.

### Proof-of-work

Encryption can optionally add a proof-of-work nonce and matching hash, controlled by `--pow-bits` and `--pow-start`. This is checked during decryption before plaintext is released.

### Benchmark and audit mode

The native and Python surfaces include speed benchmarking and optional diffusion comparison against SHA-256. The audit path records metrics such as mean flip rate, deviation from 0.5, entropy statistics, worst cells, row/column summaries, and optional pair-dependence analysis.

## Security notes

- The project-specific derivation math is custom.
- Payload confidentiality and integrity come from **XChaCha20-Poly1305**.
- Signature support comes from **Ed25519**.
- The code derives separate labeled internal roots for encryption, authentication, nonce generation, verification, and public-key seed generation.

This means the custom part of the system is the key and transport derivation layer. The actual payload AEAD and signature primitives are standard.

## Quick start

### Python

```bash
shep32 hash --text "hello"
shep32 enc --text "secret" --key "password"
```

### JavaScript / Node

```bash
node js/shepCLI.js --text "hello"
node js/shepCLI.js --encrypt "secret" --key password
```

### C++

```bash
cd cpp
./build.sh
./bin/shep32-cpp --text "hello"
./bin/shep32-cpp --encrypt "secret" --key password
```

## License

[MIT License](https://github.com/andylehti/SHEP32/blob/main/LICENSE)
