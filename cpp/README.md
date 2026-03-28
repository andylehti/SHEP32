# SHEP32 C++

The native C++ build provides the `shep32-cpp` command-line binary for hashing, encryption, decryption, signing, verification, range generation, benchmarking, and the interactive menu.

## Included files

- `shep32.cpp` — main native CLI source
- `audit.cpp` and `audit.h` — benchmark and audit support
- `build.sh` — local build script
- `install.sh` — install script for `shep32-cpp`
- `uninstall.sh` — uninstall script
- `Makefile` — simple build and install targets
- `INSTALL.md` — installation details

## Quick start

Build locally:

```bash
cd cpp
./build.sh
./bin/shep32-cpp --help
```

Install to `/usr/local`:

```bash
cd cpp
sudo ./install.sh
```

Install to a user-local prefix:

```bash
cd cpp
./install.sh --prefix "$HOME/.local"
```

When installed, the main command is:

```bash
shep32-cpp --help
```

If `shep` is not already present in `PATH`, the install script also creates a `shep` alias that points to `shep32-cpp`.

## Output location

The build script writes the binary to:

```text
cpp/bin/shep32-cpp
```

## Requirements

- `g++` with C++17 support
- Boost Multiprecision headers (`boost/multiprecision/cpp_int.hpp`)
- OpenSSL development headers and libraries
- zlib development headers and libraries

## Common commands

Generate a key from text:

```bash
./bin/shep32-cpp --text "hello"
```

Generate an extended key:

```bash
./bin/shep32-cpp --mode 1 --text "hello"
```

Encrypt text:

```bash
./bin/shep32-cpp --encrypt "secret" --key "passphrase"
```

Encrypt a file:

```bash
./bin/shep32-cpp --encrypt-file ./notes.txt --key "passphrase"
```

Decrypt a token file:

```bash
./bin/shep32-cpp --decrypt-file ./notes.sh32 --keyfile ./notes.pkey
```

Derive a public key:

```bash
./bin/shep32-cpp --pubkey --keyfile ./notes.pkey
```

Sign text:

```bash
./bin/shep32-cpp --sign "message" --keyfile ./notes.pkey
```

Verify a signature:

```bash
./bin/shep32-cpp --verify "message" --signature <signature> --public-key <publicKey>
```

Run a benchmark:

```bash
./bin/shep32-cpp --bench 1000
```
