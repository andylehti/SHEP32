# =========================
# Main imports and runtime
# Build Version: 41D

# NOTES: Core standard-library dependencies, CLI support, and runtime integer configuration.
# =========================

import math, os, sys, time, zlib, json, difflib, argparse
from pathlib import Path

sys.set_int_max_str_digits(0)

# =========================
# CLI constants and file format markers

# NOTES: Versioning, allowed extensions, key file wrappers, metadata framing bytes, and file-size guardrails.
# =========================

VERSION = "1.0.1"

DOC_EXTS = {".pdf", ".doc", ".docx", ".txt", ".rtf", ".odt", ".md", ".csv", ".xls", ".xlsx", ".json", ".tsv"}
ALLOWED_DEC_EXTS = {".shep32", ".sh3", ".sh32", ""}

KEY_HEADER = "-----BEGIN SHEP32 KEY-----\n"
KEY_FOOTER = "\n-----END SHEP32 KEY-----"

META_HEADER = b"SHEP32FILEv1\n"
META_DELIM = b"\n---\n"

DEFAULT_MAX_BYTES = 1000 * 1024

# =========================
# CLI formatting, validation, and basic file helpers

# NOTES: Error printing, hex cleanup, text/binary file access, key-file parsing/formatting, stdin payload reading, and extension/size validation.
# =========================

def printErr(msg):
    print(f"ERROR: {msg}", file=sys.stderr)

def isDirPath(p):
    try:
        return Path(p).exists() and Path(p).is_dir()
    except Exception:
        return False

def sanitizeHex64(s):
    t = "".join(ch for ch in str(s).lower().strip() if ch in "0123456789abcdef")
    return t

def readTextFile(path):
    return Path(path).read_text(encoding="utf-8", errors="replace")

def writeTextFile(path, s):
    Path(path).write_text(s, encoding="utf-8", errors="strict")

def readBinFile(path):
    return Path(path).read_bytes()

def writeBinFile(path, b):
    Path(path).write_bytes(b)

def parseKeyFileText(text):
    t = text.strip().replace("\r\n", "\n")
    if KEY_HEADER.strip() in t and KEY_FOOTER.strip() in t:
        start = t.find(KEY_HEADER.strip())
        end = t.find(KEY_FOOTER.strip(), start)
        if start >= 0 and end > start:
            mid = t[start:].split("\n", 1)[1]
            mid = mid.split(KEY_FOOTER.strip(), 1)[0].strip()
            if isHex64(mid):
                return mid.lower()
    for line in t.splitlines():
        s = sanitizeHex64(line)
        if isHex64(s):
            return s
    raise ValueError("Invalid .pkey format (expected header/footer with 64-hex inside, or a bare 64-hex line).")

def loadKeyFromFile(path):
    return parseKeyFileText(readTextFile(path))

def formatKeyFile(hex64):
    return f"{KEY_HEADER}{hex64.lower()}{KEY_FOOTER}"

def writeKeyFile(path, hex64):
    writeTextFile(path, formatKeyFile(hex64))

def validateFileCap(filePath, noLimit):
    size = Path(filePath).stat().st_size
    if (not noLimit) and size > DEFAULT_MAX_BYTES:
        raise ValueError(f"File exceeds 1000KB limit ({size} bytes). Use --no-limit to override.")

def validateDecExtension(filePath, force):
    ext = Path(filePath).suffix.lower()
    if not force and ext not in ALLOWED_DEC_EXTS:
        raise ValueError(f"Invalid decrypt extension '{ext}'. Allowed: .shep32 .sh3 .sh32 or no extension (use --force to override).")

def readStdinPayload(delim=None):
    data = sys.stdin.read()
    if delim:
        start = f"{delim}:BEGIN"
        end = f"{delim}:END"
        a = data.find(start)
        b = data.find(end, a + len(start)) if a >= 0 else -1
        if a < 0 or b < 0:
            raise ValueError(f"Delimiter block not found. Expected markers:\n{start}\n...\n{end}")
        return data[a + len(start):b].strip()
    return data.rstrip("\n\r")

def resolveKeyFromArgs(args, require=False):
    provided = 0
    if getattr(args, "key", None): provided += 1
    if getattr(args, "passphrase", None) is not None: provided += 1
    if getattr(args, "keyfile", None): provided += 1
    if provided > 1:
        raise ValueError("Provide only one of: --key, --passphrase, --keyfile")

    if getattr(args, "keyfile", None):
        return loadKeyFromFile(args.keyfile)

    if getattr(args, "passphrase", None) is not None:
        return generatePKey(args.passphrase).lower()

    if getattr(args, "key", None) is not None:
        k = sanitizeHex64(args.key)
        if not isHex64(k):
            raise ValueError("--key must be exactly 64 hex characters")
        return k

    if require:
        raise ValueError("A key source is required for decryption (--key, --passphrase, or --keyfile).")

    return ""

def emitJson(obj):
    print(json.dumps(obj, ensure_ascii=False))

# =========================
# CLI output path and naming helpers

# NOTES: Default encrypted/decrypted output naming, directory-aware output routing, and restored filename selection.
# =========================

def defaultEncOutPath(inPath):
    p = Path(inPath)
    outExt = ".sh3" if p.suffix.lower() in DOC_EXTS else ".shep32"
    return str(p.with_suffix(outExt))

def chooseEncOutPath(inPath, outArg):
    if not outArg:
        return defaultEncOutPath(inPath)
    if isDirPath(outArg):
        p = Path(inPath)
        outExt = ".sh3" if p.suffix.lower() in DOC_EXTS else ".shep32"
        return str(Path(outArg) / (p.stem + outExt))
    return str(outArg)

def chooseDecOutPath(srcPath, restoredName, outArg):
    if not outArg:
        return str(Path(srcPath).with_name(restoredName))
    if isDirPath(outArg):
        return str(Path(outArg) / restoredName)
    return str(outArg)

# =========================
# File payload framing and raw byte transforms

# NOTES: Structured file payload packing/unpacking and raw byte encryption/decryption wrappers that mirror the updated core pipeline.
# =========================

def packFilePayload(filePath, dataBytes):
    p = Path(filePath)
    name = p.stem
    ext = p.suffix
    sizeStr = str(len(dataBytes)).encode("utf-8")
    header = META_HEADER + name.encode("utf-8", errors="strict") + b"\n" + ext.encode("utf-8", errors="strict") + b"\n" + sizeStr + META_DELIM
    return header + dataBytes

def unpackFilePayload(payloadBytes):
    if not payloadBytes.startswith(META_HEADER):
        return None
    try:
        idx = payloadBytes.find(META_DELIM)
        if idx < 0:
            return None
        head = payloadBytes[:idx + len(META_DELIM)]
        rest = payloadBytes[idx + len(META_DELIM):]
        lines = head.decode("utf-8", errors="strict").split("\n")
        if len(lines) < 4:
            return None
        name = lines[1]
        ext = lines[2]
        sizeStr = lines[3].strip()
        _ = int(sizeStr)
        return (name + ext), rest
    except Exception:
        return None

def toBytesRaw(dataBytes):
    if not isinstance(dataBytes, (bytes, bytearray)):
        raise TypeError("toBytesRaw expects bytes")
    b = b"\x01" + bytes(dataBytes)
    return int.from_bytes(b, "big")

def fromBytesRaw(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if not b or b[0] != 1:
        raise ValueError("byte sentinel missing")
    return b[1:]

def encryptBytes(dataBytes, keyHexOrZero=0):
    n = toBytesRaw(dataBytes)
    if keyHexOrZero:
        if not isHex64(keyHexOrZero):
            raise ValueError("personalKey must be exactly 64 hex digits")
        hKey = str(keyHexOrZero).lower()
        e = getE(hKey)
    else:
        hKey, e = hashKey(n)
    key0 = tDecimal(hKey, 16)
    b = e

    keys = [key0]
    key = key0
    for _ in range(9):
        key = int(processKey(key))
        keys.append(key)

    n = n + (key // b)
    n = pData(n, keys, b)
    return fDecimal(n, 62), hKey

def decryptBytes(cipherStr, keyHex):
    if not isHex64(keyHex):
        raise ValueError("personalKey must be exactly 64 hex digits")
    k = keyHex.lower()
    e = getE(k)
    key0 = tDecimal(k, 16)
    b = e
    n = tDecimal(cipherStr, 62)

    keys = [key0]
    key = key0
    for _ in range(9):
        key = int(processKey(key))
        keys.append(key)

    n = dData(n, keys, b)
    n = n - (key // b)
    return fromBytesRaw(n)

# =========================
# Path normalization and discovery helpers

# NOTES: User path cleanup, existence checks, fallback path variants, bounded filesystem walking, and fuzzy suggestion ranking for wizard recovery.
# =========================

def normUserPath(s):
    if s is None:
        return ""
    s = str(s).strip()
    if not s:
        return ""
    s = os.path.expandvars(s)
    s = os.path.expanduser(s)
    return s

def existingFile(p):
    try:
        x = Path(p)
        return x.exists() and x.is_file()
    except Exception:
        return False

def existingDir(p):
    try:
        x = Path(p)
        return x.exists() and x.is_dir()
    except Exception:
        return False

def tryPathVariants(rawPath):
    rawPath = normUserPath(rawPath)
    if not rawPath:
        return []

    p = Path(rawPath)

    variants = []

    variants.append(p)

    if not p.is_absolute():
        variants.append(Path.cwd() / p)

    home = Path.home()
    if not p.is_absolute():
        variants.append(home / p)
        
    seen = set()
    out = []
    for v in variants:
        try:
            key = str(v)
        except Exception:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out

def firstExistingFile(rawPath):
    for v in tryPathVariants(rawPath):
        if existingFile(v):
            return str(Path(v).resolve())
    return None

def bestEffortSearchRoots():
    roots = []
    roots.append(Path.cwd())
    roots.append(Path.home())

    mnt = Path("/mnt")
    if mnt.exists() and mnt.is_dir():
        roots.append(mnt)

    seen = set()
    out = []
    for r in roots:
        try:
            rr = r.resolve()
        except Exception:
            rr = r
        k = str(rr)
        if k in seen:
            continue
        seen.add(k)
        if rr.exists() and rr.is_dir():
            out.append(rr)
    return out

def _sim(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()

def _walkLimited(root, maxDepth=6, maxFiles=40000):
    root = Path(root)
    rootParts = len(root.parts)
    filesSeen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        try:
            d = Path(dirpath)
            depth = len(d.parts) - rootParts
            if depth > maxDepth:
                dirnames[:] = []
                continue
        except Exception:
            continue

        for fn in filenames:
            filesSeen += 1
            if filesSeen > maxFiles:
                return
            yield d, fn

def fuzzyFindInRoot(root, rawPath, maxHits=3, maxDepth=6, maxFiles=40000):
    raw = normUserPath(rawPath)
    p = Path(raw)
    targetName = p.name if p.name else raw
    targetStem = Path(targetName).stem
    targetExt = Path(targetName).suffix

    scored = []
    for d, fn in _walkLimited(root, maxDepth=maxDepth, maxFiles=maxFiles):
        cand = Path(fn)
        candStem = cand.stem
        candExt = cand.suffix

        sStem = _sim(targetStem.lower(), candStem.lower())
        sName = _sim(targetName.lower(), fn.lower())

        extBonus = 0.0
        if targetExt:
            extBonus = 0.12 if candExt.lower() == targetExt.lower() else -0.08

        try:
            depthPenalty = (len(d.parts) - len(Path(root).parts)) * 0.01
        except Exception:
            depthPenalty = 0.0

        score = (0.65 * sStem) + (0.35 * sName) + extBonus - depthPenalty

        if score >= 0.62:
            scored.append((score, str((d / fn).resolve())))

    scored.sort(key=lambda x: x[0], reverse=True)

    out = []
    seen = set()
    for _, pathStr in scored:
        if pathStr in seen:
            continue
        seen.add(pathStr)
        out.append(pathStr)
        if len(out) >= maxHits:
            break
    return out

def rankSuggestions(rawPath):
    raw = normUserPath(rawPath)
    p = Path(raw)

    roots = []

    try:
        if p.parent and existingDir(p.parent):
            roots.append(p.parent)
    except Exception:
        pass

    roots.extend(bestEffortSearchRoots())

    rSeen = set()
    r2 = []
    for r in roots:
        try:
            rr = Path(r).resolve()
        except Exception:
            rr = Path(r)
        k = str(rr)
        if k in rSeen:
            continue
        rSeen.add(k)
        if rr.exists() and rr.is_dir():
            r2.append(rr)

    hits = []
    for i, r in enumerate(r2):
        depth = 4 if i == 0 else 6 if i == 1 else 8
        files = 20000 if i == 0 else 35000 if i == 1 else 60000
        found = fuzzyFindInRoot(r, rawPath, maxHits=6, maxDepth=depth, maxFiles=files)
        for f in found:
            if f not in hits:
                hits.append(f)
            if len(hits) >= 3:
                return hits[:3]

    return hits[:3]

# =========================
# Command handlers

# NOTES: Top-level CLI actions for key generation, encryption, and decryption, including file/text/stdin routing and optional JSON responses.
# =========================

def cmdKey(args):
    k = generatePKey(args.passphrase).lower() if args.passphrase else generatePKey().lower()
    if args.save:
        writeKeyFile(args.save, k)
        if args.json:
            emitJson({"ok": True, "mode": "key", "key": k, "saved_to": args.save})
        else:
            print(k)
            print(args.save)
        return 0
    if args.json:
        emitJson({"ok": True, "mode": "key", "key": k})
    else:
        print(k)
    return 0

def cmdEnc(args):
    k = resolveKeyFromArgs(args, require=False)
    keyArg = k if k else 0

    if args.file:
        fp = args.file
        if not Path(fp).exists():
            raise FileNotFoundError(fp)

        validateFileCap(fp, args.no_limit)

        data = readBinFile(fp)
        payload = packFilePayload(fp, data)
        c, used = encryptBytes(payload, keyArg)

        outPath = chooseEncOutPath(fp, args.out)
        writeTextFile(outPath, c)

        if args.write_key:
            writeKeyFile(args.write_key, used)

        else:
            print("")
            print("Remember to save your key or else you cannot decrypt your file.")

            choice = input(
                "Would you like it displayed in terminal or saved as a key file? [d/s] (default: s): "
            ).strip().lower()

            if choice in {"", "s", "save"}:
                outP = Path(outPath)
                defaultKeyPath = str(outP.with_suffix(outP.suffix + ".pkey"))

                nameOrPath = input(
                    "Name/path for key file (blank = default next to encrypted file): "
                ).strip()

                if nameOrPath:
                    kp = Path(normUserPath(nameOrPath))

                    if isDirPath(kp):
                        keyPath = str(Path(kp) / Path(defaultKeyPath).name)
                    else:
                        keyPath = str(kp)
                        if not keyPath.lower().endswith(".pkey"):
                            keyPath += ".pkey"
                else:
                    keyPath = defaultKeyPath

                writeKeyFile(keyPath, used)
                print(f"Wrote key file: {keyPath}", file=sys.stderr)

            else:
                if not args.quiet_key:
                    print(used)

        if args.json:
            emitJson({
                "ok": True,
                "mode": "enc",
                "input": "file",
                "out": outPath,
                "key": used,
                "cipher_len": len(c)
            })
        else:
            print(outPath)

        return 0

    if args.stdin:
        pt = readStdinPayload(args.delim)
    else:
        pt = args.text

    c, used = encryptData(pt, keyArg)

    if args.write_key:
        writeKeyFile(args.write_key, used)

    if args.out:
        writeTextFile(args.out, c)

        if args.json:
            emitJson({
                "ok": True,
                "mode": "enc",
                "input": "text",
                "out": args.out,
                "key": used,
                "cipher_len": len(c)
            })
        else:
            print(args.out)
            if not args.quiet_key:
                print(used)

        return 0

    if args.json:
        emitJson({
            "ok": True,
            "mode": "enc",
            "input": "text",
            "ciphertext": c,
            "key": used
        })
    else:
        print(c)
        if not args.quiet_key:
            print(used)

    return 0

def cmdDec(args):
    k = resolveKeyFromArgs(args, require=True)

    if args.file:
        fp = args.file
        if not Path(fp).exists():
            raise FileNotFoundError(fp)
        validateDecExtension(fp, args.force)

        cipherStr = readTextFile(fp).strip()
        payloadBytes = decryptBytes(cipherStr, k)
        unpacked = unpackFilePayload(payloadBytes)

        if unpacked:
            restoredName, raw = unpacked
            outPath = chooseDecOutPath(fp, restoredName, args.out)
            writeBinFile(outPath, raw)
            if args.json:
                emitJson({"ok": True, "mode": "dec", "input": "file", "out": outPath, "restored_name": restoredName})
            else:
                print(outPath)
            return 0

        if args.as_text:
            try:
                s = payloadBytes.decode("utf-16-le", errors="surrogatepass")
                if args.json:
                    emitJson({"ok": True, "mode": "dec", "input": "file", "as_text": True, "plaintext_len": len(s)})
                else:
                    print(s)
                return 0
            except Exception:
                try:
                    s = payloadBytes.decode("utf-8")
                except Exception:
                    s = payloadBytes.decode("latin-1")
                if args.json:
                    emitJson({"ok": True, "mode": "dec", "input": "file", "as_text": True, "plaintext_len": len(s)})
                else:
                    print(s)
                return 0

        outPath = args.out or str(Path(fp).with_name("restored.bin"))
        writeBinFile(outPath, payloadBytes)
        if args.json:
            emitJson({"ok": True, "mode": "dec", "input": "file", "out": outPath})
        else:
            print(outPath)
        return 0

    if args.stdin:
        ct = readStdinPayload(args.delim).strip()
    else:
        ct = args.text.strip()

    payloadBytes = decryptBytes(ct, k)
    unpacked = unpackFilePayload(payloadBytes)

    if unpacked and not args.as_text:
        restoredName, raw = unpacked
        outPath = args.out or restoredName
        writeBinFile(outPath, raw)
        if args.json:
            emitJson({"ok": True, "mode": "dec", "input": "text", "out": outPath, "restored_name": restoredName})
        else:
            print(outPath)
        return 0

    pt = payloadBytes.decode("utf-16-le", errors="surrogatepass")

    if args.out:
        writeTextFile(args.out, pt)
        if args.json:
            emitJson({"ok": True, "mode": "dec", "input": "text", "out": args.out, "plaintext_len": len(pt)})
        else:
            print(args.out)
        return 0

    if args.json:
        emitJson({"ok": True, "mode": "dec", "input": "text", "as_text": True, "plaintext_len": len(pt)})
    else:
        print(pt)
    return 0

# =========================
# Interactive wizard and recovery flow

# NOTES: Guided terminal workflow for encrypt/decrypt/key tasks and path-recovery assistance when a requested file cannot be found.
# =========================

def interactiveWizard():
    print("SHEP32 Interactive Wizard")
    print("1) Encrypt  2) Decrypt  3) Generate Key  4) Exit")
    choice = input("> ").strip()
    if choice in {"4", "q", "quit", "exit"}:
        return 0

    if choice == "3":
        try:
            phrase = input("Passphrase (blank = random): ").strip()
            k = generatePKey(phrase).lower() if phrase else generatePKey().lower()
            print(k)
            save = input("Save to .pkey file? (path/blank to skip): ").strip()
            if save:
                writeKeyFile(save, k)
                print(f"Wrote {save}", file=sys.stderr)
            return 0
        except Exception as e:
            printErr(str(e))
            return 2

    isEnc = (choice == "1")
    kind = input("Input type:    1) File  2) Text : ").strip()

    if kind == "1":
        fpRaw = input("File path: ").strip()
        fp = wizardPickExistingPath(fpRaw, label="File")
        if not fp:
            return 0

        if isEnc:
            class A: pass
            a = A()
            a.file = fp; a.text = None; a.stdin = False; a.delim = None
            a.key = None; a.passphrase = None; a.keyfile = None
            a.out = None; a.no_limit = False; a.quiet_key = False; a.write_key = None; a.json = False
            try:
                return cmdEnc(a)
            except Exception as e:
                printErr(str(e))
                return 2

        class B: pass
        b = B()
        b.file = fp; b.text = None; b.stdin = False; b.delim = None
        b.key = input("Key (64-hex) or blank to use keyfile/passphrase: ").strip() or None
        b.passphrase = None; b.keyfile = None
        b.out = None; b.as_text = False; b.force = False; b.json = False

        if not b.key:
            b.keyfile = input("Keyfile (.pkey) path or blank: ").strip() or None
            if not b.keyfile:
                b.passphrase = input("Passphrase or blank: ").strip() or None

        try:
            return cmdDec(b)
        except Exception as e:
            printErr(str(e))
            return 2

    if kind == "2":
        if isEnc:
            pt = input("Plaintext: ")
            class A: pass
            a = A()
            a.file = None; a.text = pt; a.stdin = False; a.delim = None
            a.key = None; a.passphrase = None; a.keyfile = None
            a.out = None; a.no_limit = False; a.quiet_key = False; a.write_key = None; a.json = False
            try:
                return cmdEnc(a)
            except Exception as e:
                printErr(str(e))
                return 2

        ct = input("Ciphertext (base62): ").strip()
        class B: pass
        b = B()
        b.file = None; b.text = ct; b.stdin = False; b.delim = None
        b.key = input("Key (64-hex): ").strip()
        b.passphrase = None; b.keyfile = None
        b.out = None; b.as_text = True; b.force = False; b.json = False
        try:
            return cmdDec(b)
        except Exception as e:
            printErr(str(e))
            return 2

    printErr("Unknown selection.")
    return 2
    printErr("Unknown selection.")
    return 2

def wizardPickExistingPath(rawPath, label="File"):
    rawPath = str(rawPath).strip()
    resolved = firstExistingFile(rawPath)
    if resolved:
        return resolved

    tried = [str(v) for v in tryPathVariants(rawPath)]
    print(f"Could not find {label}: {rawPath}")
    print("Tried:")
    for t in tried:
        print(f" - {t}")

    sug = rankSuggestions(rawPath)
    if not sug:
        print("No suggestions found.")
        return None

    print("\nSuggestions:")
    for i, s in enumerate(sug, 1):
        print(f"{i}) {s}")
    print("4) Quit")

    while True:
        pick = input("> ").strip()
        if pick == "4":
            return None
        if pick in {"1", "2", "3"}:
            idx = int(pick) - 1
            if idx < len(sug) and existingFile(sug[idx]):
                return str(Path(sug[idx]).resolve())
            print("That selection is no longer available.")
            return None
        print("Choose 1, 2, 3, or 4.")

# =========================
# Argument parser definition

# NOTES: argparse command tree for start, key, encrypt, and decrypt modes with shared compatibility aliases and output controls.
# =========================

def buildParser():
    parser = argparse.ArgumentParser(
        prog="shep32",
        description="SHEP32 CLI (enc/dec/key/start)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("start", help="Interactive guided workflow")

    pk = sub.add_parser("key", help="Generate / derive a 64-hex key")
    pk.add_argument("-p", "--passphrase", default=None, help="Derive from passphrase (deterministic)")
    pk.add_argument("--save", default=None, help="Save key as .pkey file")
    pk.add_argument("--json", action="store_true", help="Output JSON")

    pe = sub.add_parser("enc", help="Encrypt file or plaintext")
    srcE = pe.add_mutually_exclusive_group(required=True)
    srcE.add_argument("-f", "--file", dest="file", default=None, help="File path to encrypt")
    srcE.add_argument("--text", dest="text", default=None, help="Plaintext to encrypt")
    srcE.add_argument("-e", dest="text", default=None, help="Alias for --text (compat)")
    srcE.add_argument("--stdin", action="store_true", help="Read plaintext from stdin")

    pe.add_argument("--delim", default=None, help="Optional delimiter markers for stdin: DELIM:BEGIN ... DELIM:END")

    keyE = pe.add_mutually_exclusive_group(required=False)
    keyE.add_argument("--key", default=None, help="64-hex key")
    keyE.add_argument("-p", "--passphrase", default=None, help="Derive from passphrase")
    keyE.add_argument("--keyfile", default=None, help="Load key from .pkey file")

    pe.add_argument("-o", "--out", default=None, help="Output file path (or directory for file mode)")
    pe.add_argument("--no-limit", dest="no_limit", action="store_true", help="Override 100KB file limit")
    pe.add_argument("--quiet-key", dest="quiet_key", action="store_true", help="Do not print the key to stdout")
    pe.add_argument("--write-key", dest="write_key", default=None, help="Write used key to .pkey file")
    pe.add_argument("--json", action="store_true", help="Output JSON")

    pd = sub.add_parser("dec", help="Decrypt file or ciphertext")
    srcD = pd.add_mutually_exclusive_group(required=True)
    srcD.add_argument("-f", "--file", dest="file", default=None, help="File path to decrypt (.shep32/.sh3/.sh32 or extensionless)")
    srcD.add_argument("--text", dest="text", default=None, help="Ciphertext (base62) to decrypt")
    srcD.add_argument("-d", dest="text", default=None, help="Alias for --text (compat)")
    srcD.add_argument("--stdin", action="store_true", help="Read ciphertext from stdin")

    pd.add_argument("--delim", default=None, help="Optional delimiter markers for stdin: DELIM:BEGIN ... DELIM:END")

    keyD = pd.add_mutually_exclusive_group(required=True)
    keyD.add_argument("--key", default=None, help="64-hex key")
    keyD.add_argument("-p", "--passphrase", default=None, help="Derive from passphrase")
    keyD.add_argument("--keyfile", default=None, help="Load key from .pkey file")

    pd.add_argument("-o", "--out", default=None, help="Output file path (or directory for restored file)")
    pd.add_argument("--as-text", dest="as_text", action="store_true", help="Print plaintext to stdout (for file decrypt, when not structured)")
    pd.add_argument("--force", action="store_true", help="Ignore extension rules")
    pd.add_argument("--json", action="store_true", help="Output JSON")

    return parser

# =========================
# Main entrypoint and exception routing

# NOTES: Top-level command dispatch, zero-arg wizard fallback, CLI exit codes, and standardized exception handling.
# =========================

def main(argv=None):
    parser = buildParser()
    args = parser.parse_args(argv)

    if args.cmd is None:
        if argv is None and len(sys.argv) == 1:
            return interactiveWizard()
        parser.print_help()
        return 2
    try:
        if args.cmd is None:
            if argv is None and len(sys.argv) == 1:
                return interactiveWizard()
            parser.print_help()
            return 2
        if args.cmd == "start":
            return interactiveWizard()
        if args.cmd == "key":
            return cmdKey(args)
        if args.cmd == "enc":
            return cmdEnc(args)
        if args.cmd == "dec":
            return cmdDec(args)

        printErr("Unknown command.")
        return 2
    except FileNotFoundError as e:
        printErr(f"File not found: {e}")
        return 3
    except ValueError as e:
        printErr(str(e))
        return 3
    except KeyboardInterrupt:
        printErr("Operation cancelled by user.")
        return 130
    except Exception as e:
        printErr(f"Unexpected runtime error: {e}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())