# Installing the C++ Binary

## Build

From the `cpp` directory:

```bash
./build.sh
```

This produces:

```text
./bin/shep32-cpp
```

## Install

System-wide install:

```bash
sudo ./install.sh
```

User-local install:

```bash
./install.sh --prefix "$HOME/.local"
```

Custom binary name:

```bash
./install.sh --bin-name shep32-cpp
```

## Installed commands

The installer places the native binary at:

```text
<prefix>/bin/shep32-cpp
```

If no `shep` command is already found in `PATH`, the installer also creates:

```text
<prefix>/bin/shep
```

That alias points to `shep32-cpp`.

## Uninstall

System-wide uninstall:

```bash
sudo ./uninstall.sh
```

User-local uninstall:

```bash
./uninstall.sh --prefix "$HOME/.local"
```

## Make targets

Build:

```bash
make
```

Install:

```bash
sudo make install
```

Uninstall:

```bash
sudo make uninstall
```
