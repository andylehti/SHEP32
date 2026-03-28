# =========================
# CLI imports and user-facing workflow
# CLI Build Version: 2.0.2
# NOTES: Argument parsing, key-file handling, file payload wrappers, range generation, signing helpers, and interactive command routing.
# =========================

import argparse, difflib, hashlib, json, os, sys, time
from pathlib import Path

try:
    from .core import *
    from .core import _printProg
except Exception:
    try:
        from shep32.core import *
        from shep32.core import _printProg
    except Exception:
        try:
            from shep32 import *
            from shep32 import _printProg
        except Exception:
            from shep32 import *
            from shep32 import _printProg

CLI_VERSION = "2.1.0"

DOC_EXTS = {".pdf", ".doc", ".docx", ".txt", ".rtf", ".odt", ".md", ".csv", ".xls", ".xlsx", ".json", ".tsv", ".bin"}
KEY_HEADER = "-----BEGIN SHEP KEY-----\n"
KEY_FOOTER = "\n-----END SHEP KEY-----"
FILE_MARKER = "__shep_file__"
DEFAULT_MAX_BYTES = 1000 * 1024
CHUNK_UNIT = 2048
FIXED_COUNT = 8

def printErr(msg):
    print(f"ERROR: {msg}", file=sys.stderr)

def isDirPath(p):
    try:
        return Path(p).exists() and Path(p).is_dir()
    except Exception:
        return False

def readTextFile(path):
    return Path(path).read_text(encoding="utf-8", errors="replace")

def writeTextFile(path, s):
    Path(path).write_text(s, encoding="utf-8", errors="strict")

def readBinFile(path):
    return Path(path).read_bytes()

def writeBinFile(path, b):
    Path(path).write_bytes(b)

def sanitizeKeyToken(s):
    return str(s).strip()

def isKeyToken(s, count=8):
    if not isinstance(s, str):
        return False
    t = s.strip()
    return isHex64(t) or isExtendedKey(t, count)

def parseKeyFileText(text):
    t = text.strip().replace("\r\n", "\n")
    wrappers = [
        (KEY_HEADER.strip(), KEY_FOOTER.strip()),
        ("-----BEGIN SHEP KEY-----", "-----END SHEP KEY-----"),
        ("-----BEGIN SHEP32 KEY-----", "-----END SHEP32 KEY-----"),
        ("-----BEGIN SHEP64 KEY-----", "-----END SHEP64 KEY-----"),
        ("-----BEGIN SHEP333 KEY-----", "-----END SHEP333 KEY-----"),
    ]
    for head, foot in wrappers:
        if head in t and foot in t:
            start = t.find(head)
            end = t.find(foot, start)
            if start >= 0 and end > start:
                mid = t[start:].split("\n", 1)[1]
                mid = mid.split(foot, 1)[0].strip()
                if mid:
                    return mid
    for line in t.splitlines():
        s = line.strip()
        if s:
            return s
    raise ValueError("Invalid key file format.")

def loadKeyFromFile(path):
    return parseKeyFileText(readTextFile(path))

def formatKeyFile(token):
    return f"{KEY_HEADER}{str(token).strip()}{KEY_FOOTER}"

def writeKeyFile(path, token):
    writeTextFile(path, formatKeyFile(token))

def validateFileCap(filePath, noLimit):
    size = Path(filePath).stat().st_size
    if (not noLimit) and size > DEFAULT_MAX_BYTES:
        raise ValueError(f"File exceeds {DEFAULT_MAX_BYTES} byte limit ({size} bytes). Use --no-limit to override.")

def resolveChunkBytes(chunkSize=None, chunkBytes=None, defaultUnits=1):
    if chunkBytes is not None:
        out = int(chunkBytes)
    else:
        units = defaultUnits if chunkSize is None else int(chunkSize)
        out = int(units) * CHUNK_UNIT
    if out < 1:
        raise ValueError("Chunk size must be >= 1 byte.")
    return out

def makeProgress(label):
    state = {"last": None}
    def emit(done, total, stage=""):
        total = max(1, int(total))
        done = max(0, min(int(done), total))
        pct = int((done * 100) / total)
        sig = (pct, stage)
        if state["last"] == sig and done < total:
            return
        state["last"] = sig
        width = 32
        fill = int((pct * width) / 100)
        bar = "█" * fill + "·" * (width - fill)
        extra = f"  {stage}" if stage else ""
        sys.stdout.write(f"\r{label} [{bar}] {pct:3d}% {done}/{total}{extra}")
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()
    return emit

def packFilePayload(filePath, dataBytes):
    obj = {
        FILE_MARKER: 1,
        "name": Path(filePath).name,
        "size": len(dataBytes),
        "data": packPortableBytes(dataBytes),
    }
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def unpackFilePayload(text):
    try:
        obj = json.loads(text)
    except Exception:
        return None
    if not isinstance(obj, dict) or int(obj.get(FILE_MARKER, 0)) != 1:
        return None
    name = str(obj.get("name", "restored.bin"))
    data = unpackPortableBytes(str(obj["data"]))
    return name, data

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

def maybeLoadToken(value):
    s = str(value).strip()
    try:
        p = Path(os.path.expanduser(os.path.expandvars(s)))
        if p.exists() and p.is_file():
            return readTextFile(p).strip()
    except Exception:
        pass
    return s


class CliFmt(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass

def normalizeMode(raw, allowNone=False, default=0):
    if raw is None:
        return None if allowNone else int(default)
    raw = int(raw)
    if raw not in (0, 1):
        raise ValueError("--mode must be 0 or 1")
    return raw

def detectExplicitKeyMode(token, count=8):
    t = sanitizeKeyToken(token)
    if isHex64(t):
        return 0
    if isExtendedKey(t, count):
        return 1
    return None

def resolveKeyInput(args, require=False, allowModeAuto=False):
    provided = 0
    if getattr(args, "key", None) is not None: provided += 1
    if getattr(args, "phrase", None) is not None: provided += 1
    if getattr(args, "keyfile", None): provided += 1
    if provided > 1:
        raise ValueError("Provide only one of: --key, --phrase, --keyfile")
    modeArg = normalizeMode(getattr(args, "mode", None), allowNone=allowModeAuto, default=0)
    if getattr(args, "keyfile", None):
        token = loadKeyFromFile(args.keyfile)
        det = detectExplicitKeyMode(token, FIXED_COUNT)
        if det is None:
            raise ValueError("Key file must contain an explicit SHEP32 or SHEP333 key.")
        if modeArg is not None and modeArg != det:
            raise ValueError(f"--mode {modeArg} does not match the key in {args.keyfile}.")
        return token, det
    if getattr(args, "key", None) is not None:
        token = sanitizeKeyToken(args.key)
        det = detectExplicitKeyMode(token, FIXED_COUNT)
        if det is None:
            raise ValueError("--key expects an explicit SHEP32 or SHEP333 key. Use --phrase for phrases.")
        if modeArg is not None and modeArg != det:
            raise ValueError(f"--mode {modeArg} does not match the explicit key provided with --key.")
        return token, det
    if getattr(args, "phrase", None) is not None:
        return args.phrase, (0 if modeArg is None else modeArg)
    if require:
        raise ValueError("A key source is required. Use --key, --phrase, or --keyfile.")
    return None, (0 if modeArg is None else modeArg)

def modeLabel(mode):
    return "SHEP32" if int(mode) == 0 else "SHEP333"

def keyInputHelp():
    return (
        "Key input rules:\n"
        "  --key      explicit SHEP32 or SHEP333 key only\n"
        "  --phrase   explicit phrase, even if it looks like a key\n"
        "  --keyfile  file containing an explicit SHEP32 or SHEP333 key\n"
        "\n"
        "Mode rules:\n"
        "  --mode 0   SHEP32 primary mode\n"
        "  --mode 1   SHEP333 extended mode\n"
        "\n"
        "Examples:\n"
        "  shep32 enc --text \"secret\" --key \"9ab70f...07dd\"\n"
        "  shep32 enc --text \"secret\" --key \"<shep333-key>\" --mode 1\n"
        "  shep32 enc --text \"secret\" --phrase \"1234\" --mode 1\n"
        "  shep32 dec --text \"<token>\" --key \"9ab70f...07dd\"\n"
        "  shep32 dec --text \"<token>\" --phrase \"1234\" --mode 1"
    )


def emitJson(obj):
    print(json.dumps(obj, ensure_ascii=False))

def defaultEncOutPath(inPath, detached=False):
    p = Path(inPath)
    if detached:
        base = p.with_suffix("")
        return str(base) + ".body", str(base) + ".meta"
    return str(p.with_suffix(".sh32"))

def chooseDetachedOutPaths(srcLabel, outArg):
    if not outArg:
        return None, None
    if isDirPath(outArg):
        stem = Path(srcLabel).stem if srcLabel else "cipher"
        return str(Path(outArg) / f"{stem}.body"), str(Path(outArg) / f"{stem}.meta")
    base = str(outArg)
    return base + ".body", base + ".meta"

def chooseTextOutPath(outArg, defaultName="cipher.sh32"):
    if not outArg:
        return None
    if isDirPath(outArg):
        return str(Path(outArg) / defaultName)
    p = Path(str(outArg))
    if p.suffix == "":
        return str(p.with_suffix(".sh32"))
    return str(p)

def chooseDecOutPath(srcPath, restoredName, outArg):
    if not outArg:
        return restoredName
    if isDirPath(outArg):
        return str(Path(outArg) / restoredName)
    return str(outArg)


def defaultKeyOutPath(cipherPath):
    p = Path(cipherPath)
    if p.suffix:
        return str(p.with_suffix(".pkey"))
    return str(Path(str(p) + ".pkey"))

def normUserPath(s):
    if s is None:
        return ""
    s = str(s).strip()
    if not s:
        return ""
    return os.path.expanduser(os.path.expandvars(s))

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
    variants = [p]
    if not p.is_absolute():
        variants.append(Path.cwd() / p)
        variants.append(Path.home() / p)
    seen = set()
    out = []
    for v in variants:
        k = str(v)
        if k not in seen:
            seen.add(k)
            out.append(v)
    return out

def firstExistingFile(rawPath):
    for v in tryPathVariants(rawPath):
        if existingFile(v):
            return str(Path(v).resolve())
    return None

def bestEffortSearchRoots():
    roots = [Path.cwd(), Path.home()]
    mnt = Path("/mnt")
    if mnt.exists() and mnt.is_dir():
        roots.append(mnt)
    out = []
    seen = set()
    for r in roots:
        try:
            rr = r.resolve()
        except Exception:
            rr = r
        k = str(rr)
        if k not in seen and rr.exists() and rr.is_dir():
            seen.add(k)
            out.append(rr)
    return out

def _sim(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()

def _walkLimited(root, maxDepth=6, maxFiles=40000):
    root = Path(root)
    rootParts = len(root.parts)
    filesSeen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        depth = len(d.parts) - rootParts
        if depth > maxDepth:
            dirnames[:] = []
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
        sStem = _sim(targetStem.lower(), cand.stem.lower())
        sName = _sim(targetName.lower(), fn.lower())
        extBonus = 0.12 if targetExt and cand.suffix.lower() == targetExt.lower() else 0.0
        score = (0.65 * sStem) + (0.35 * sName) + extBonus
        if score >= 0.62:
            scored.append((score, str((d / fn).resolve())))
    scored.sort(key=lambda x: x[0], reverse=True)
    out = []
    seen = set()
    for _, pathStr in scored:
        if pathStr not in seen:
            seen.add(pathStr)
            out.append(pathStr)
        if len(out) >= maxHits:
            break
    return out

def rankSuggestions(rawPath):
    roots = bestEffortSearchRoots()
    hits = []
    for i, r in enumerate(roots):
        depth = 4 if i == 0 else 6
        files = 20000 if i == 0 else 50000
        for f in fuzzyFindInRoot(r, rawPath, maxHits=6, maxDepth=depth, maxFiles=files):
            if f not in hits:
                hits.append(f)
            if len(hits) >= 3:
                return hits[:3]
    return hits[:3]

def wizardPickExistingPath(rawPath, label="File"):
    rawPath = str(rawPath).strip()
    resolved = firstExistingFile(rawPath)
    if resolved:
        return resolved
    tried = [str(v) for v in tryPathVariants(rawPath)]
    print(f"Could not find {label}: {rawPath}")
    if tried:
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
    print(f"{len(sug)+1}) Quit")
    while True:
        pick = input("> ").strip()
        if pick == str(len(sug)+1):
            return None
        if pick.isdigit():
            idx = int(pick) - 1
            if 0 <= idx < len(sug) and existingFile(sug[idx]):
                return str(Path(sug[idx]).resolve())
        print("Choose one of the listed options.")

def parseMaybeInt(s):
    return int(str(s).strip())

def printProgBar(label, done, total, started):
    if total <= 0:
        return
    frac = max(0.0, min(1.0, float(done) / float(total)))
    barW = 30
    fill = int(frac * barW)
    elapsed = int(time.perf_counter() - started)
    bar = "#" * fill + "." * (barW - fill)
    sys.stderr.write(f"\r{label} [{bar}] {int(frac*100):3d}% {done}/{total} elapsed {elapsed}s")
    sys.stderr.flush()
    if done >= total:
        sys.stderr.write("\n")
        sys.stderr.flush()

def generateHashRange(start, hashes, mode=0, count=8, directBits=256, laneBits=336, blockBytes=4096, bare=False, showProgress=False, label="HASH"):
    out = []
    cur = int(start)
    started = time.perf_counter()
    for i in range(int(hashes)):
        h = generateKey(str(cur), mode, count, directBits, laneBits, blockBytes)
        out.append(h if bare else f"{cur} = {h}")
        cur += 1
        if showProgress:
            printProgBar(label, i + 1, int(hashes), started)
    return out

def writeHashRange(path, start, hashes, mode=0, count=8, directBits=256, laneBits=336, blockBytes=4096, bare=False, showProgress=True, label="HASH"):
    with open(path, "w", encoding="utf-8", newline="\n") as fp:
        cur = int(start)
        started = time.perf_counter()
        for i in range(int(hashes)):
            h = generateKey(str(cur), mode, count, directBits, laneBits, blockBytes)
            fp.write((h if bare else f"{cur} = {h}") + "\n")
            cur += 1
            if showProgress:
                printProgBar(label, i + 1, int(hashes), started)

def randBits(nBits):
    nBits = max(1, int(nBits))
    raw = int.from_bytes(os.urandom((nBits + 7) // 8), "big")
    return raw & ((1 << nBits) - 1)

def makeBenchInputs(hashes, start=None, inputBits=256, randomInputs=True):
    hashes = int(hashes)
    if hashes < 1:
        raise ValueError("hashes must be >= 1")
    if randomInputs:
        return [randBits(inputBits) for _ in range(hashes)]
    base = 0 if start is None else int(start)
    return [base + i for i in range(hashes)]

def sha256NumHex(x):
    return hashlib.sha256(str(int(x)).encode("ascii")).hexdigest()

def meanFlipRate(hexA, hexB):
    a = int(hexA, 16)
    b = int(hexB, 16)
    return ((a ^ b).bit_count()) / 256.0

def benchSpeed(inputs, mode=0, count=8, directBits=256, laneBits=336, blockBytes=4096, showProgress=True, label="Benchmarking"):
    started = time.perf_counter()
    last = ""
    hashList = []
    total = len(inputs)
    for i, x in enumerate(inputs, 1):
        last = generateKey(str(x), mode, count, directBits, laneBits, blockBytes)
        hashList.append(last)
        if showProgress:
            _printProg(label, i, total)
    elapsed = time.perf_counter() - started
    rate = (float(total) / elapsed) if elapsed > 0 else 0.0
    return {"hashes": total, "elapsed": elapsed, "hashesPerSec": rate, "last": last, "hashList": hashList}

def benchCompare(inputs, mode=0, count=8, directBits=256, laneBits=336, blockBytes=4096, inputBits=256, compareBits=None, showProgress=True, label="Diffusion report"):
    testedBits = parseCompareBits(compareBits, inputBits)
    total = len(inputs) * (int(testedBits) + 1) * 2
    done = 0
    shepBase = []
    shaBase = []
    for x in inputs:
        shepBase.append(generateKey(str(x), mode, count, directBits, laneBits, blockBytes))
        done += 1
        if showProgress: _printProg(label, done, total)
    for x in inputs:
        shaBase.append(sha256NumHex(x))
        done += 1
        if showProgress: _printProg(label, done, total)
    shepFlip = 0.0
    shaFlip = 0.0
    cells = len(inputs) * int(testedBits)
    for bit in range(int(testedBits)):
        mask = 1 << bit
        for i, x in enumerate(inputs):
            shepFlip += meanFlipRate(shepBase[i], generateKey(str(x ^ mask), mode, count, directBits, laneBits, blockBytes))
            done += 1
            if showProgress: _printProg(label, done, total)
        for i, x in enumerate(inputs):
            shaFlip += meanFlipRate(shaBase[i], sha256NumHex(x ^ mask))
            done += 1
            if showProgress: _printProg(label, done, total)
    return {
        "samples": len(inputs),
        "inputBits": int(inputBits),
        "testedBits": int(testedBits),
        "shepMeanFlipRate": (shepFlip / cells) if cells else 0.0,
        "sha256MeanFlipRate": (shaFlip / cells) if cells else 0.0,
    }

def saveBenchReport(path, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as fp:
        for k, v in rows:
            fp.write(f"{k}\t{v}\n")

def parseCompareBits(raw, inputBits):
    if raw is None:
        return int(inputBits)
    s = str(raw).strip().lower()
    if s == "all":
        return int(inputBits)
    try:
        n = int(s)
    except Exception:
        raise ValueError("--bits must be an integer or 'all'")
    if n < 1:
        raise ValueError("--bits must be >= 1")
    return min(int(inputBits), n)

def defaultBenchHashesPath(hashes, mode=0, start=None, randomInputs=True, inputBits=256, compare=False, compareBits=None):
    parts = [f"hashes_h{int(hashes)}", f"m{int(mode)}"]
    if randomInputs:
        parts.append(f"rand{int(inputBits)}")
    else:
        parts.append(f"start{int(start) if start is not None else 0}")
    if compare:
        parts.append("cmp")
        parts.append(f"bits{compareBits if compareBits is not None else int(inputBits)}")
    return "_".join(parts) + ".txt"

def saveBenchHashes(path, inputs, hashes):
    with open(path, "w", encoding="utf-8", newline="\n") as fp:
        for x, h in zip(inputs, hashes):
            fp.write(f"{int(x)} = {h}\n")



def benchRange(start=None, hashes=0, mode=0, count=8, directBits=256, laneBits=336, blockBytes=4096, randomInputs=True, inputBits=256, compare=False, compareBits=None, out=None, hashesOut=None, showProgress=True):
    inputs = makeBenchInputs(hashes, start=start, inputBits=inputBits, randomInputs=randomInputs)
    speed = benchSpeed(inputs, mode, count, directBits, laneBits, blockBytes, showProgress, "Benchmarking")
    rows = [("hashes", speed["hashes"]), ("elapsed", f"{speed['elapsed']:.6f}"), ("hashesPerSec", f"{speed['hashesPerSec']:.6f}"), ("last", speed["last"]), ("randomInputs", str(bool(randomInputs)).lower()), ("inputBits", int(inputBits))]
    if compare:
        comp = benchCompare(inputs, mode, count, directBits, laneBits, blockBytes, inputBits, compareBits, showProgress, "Diffusion report")
        rows.extend([("testedBits", int(comp["testedBits"])), ("shepMeanFlipRate", f"{comp['shepMeanFlipRate']:.10f}"), ("sha256MeanFlipRate", f"{comp['sha256MeanFlipRate']:.10f}")])
    if hashesOut is None:
        hashesOut = defaultBenchHashesPath(hashes, mode, start, randomInputs, inputBits, compare, parseCompareBits(compareBits, inputBits) if compare else None)
    saveBenchHashes(hashesOut, inputs, speed["hashList"])
    rows.append(("hashesOut", hashesOut))
    if out:
        saveBenchReport(out, rows)
        print(out)
    else:
        for k, v in rows:
            print(f"{k}={v}")

def _fileHash(path, mode=0, count=8, directBits=256, laneBits=336, blockBytes=65536):
    return generateKeyFile(path, mode, count, directBits, laneBits, blockBytes)

def cmdKey(args):
    mode = normalizeMode(args.mode, default=0)
    if args.file:
        k = _fileHash(args.file, mode, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes)
    elif args.text is not None:
        k = generateKey(args.text, mode, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes)
    elif args.phrase is not None:
        k = generateKey(args.phrase, mode, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes)
    else:
        k = generateKey(None, mode, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes)
    if args.save:
        writeKeyFile(args.save, k)
    if args.json:
        emitJson({"ok": True, "mode": "key", "key": k, "saved_to": args.save})
    else:
        print(k)
        if args.save:
            print(args.save)
    return 0

def cmdHash(args):
    mode = normalizeMode(args.mode, default=0)
    if args.file:
        out = _fileHash(args.file, mode, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes)
    else:
        out = generateKey(args.text, mode, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes)
    if args.json:
        emitJson({"ok": True, "mode": "hash", "value": out})
    else:
        print(out)
    return 0

def cmdRange(args):
    lines = generateHashRange(args.start, args.hashes, args.mode, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes, args.bare, args.progress)
    if args.out:
        writeTextFile(args.out, "\n".join(lines) + ("\n" if lines else ""))
        print(args.out)
    else:
        for line in lines:
            print(line)
    return 0

def cmdBench(args):
    randomInputs = True if args.random_inputs is None and args.start is None else bool(args.random_inputs)
    benchRange(args.start, args.hashes, args.mode, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes, randomInputs, args.input_bits, args.compare, args.bits, args.out, args.hashes_out, not args.no_progress)
    return 0

def cmdPair(args):
    mode = normalizeMode(args.mode, default=0)
    keyMode = 0 if mode == 0 else 333
    if args.file:
        master = _fileHash(args.file, 0 if keyMode == 0 else 1, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes)
    else:
        master = generateKey(args.text, 0 if keyMode == 0 else 1, FIXED_COUNT, args.direct_bits, args.lane_bits, args.block_bytes)
    pair = computeKeyPair(master, keyMode, FIXED_COUNT)
    if args.json:
        emitJson({"ok": True, "mode": "pair", **pair})
    else:
        for k, v in pair.items():
            print(f"{k}={v}")
    return 0

def cmdPubKey(args):
    k, mode = resolveKeyInput(args, require=True, allowModeAuto=False)
    keyMode = 0 if mode == 0 else 333
    pub = generatePublicKey(k, keyMode, FIXED_COUNT)
    if args.json:
        emitJson({"ok": True, "mode": "pubkey", "publicKey": pub})
    else:
        print(pub)
    return 0

def cmdSign(args):
    k, mode = resolveKeyInput(args, require=True, allowModeAuto=False)
    keyMode = 0 if mode == 0 else 333
    payload = readTextFile(args.file) if args.file else (readStdinPayload(args.delim) if args.stdin else args.text)
    sig = signData(payload, k, keyMode, FIXED_COUNT)
    if args.json:
        emitJson({"ok": True, "mode": "sign", **sig})
    else:
        print(f"signature={sig['signature']}")
        print(f"publicKey={sig['publicKey']}")
    return 0

def cmdVerify(args):
    payload = readTextFile(args.file) if args.file else (readStdinPayload(args.delim) if args.stdin else args.text)
    signature = maybeLoadToken(args.signature)
    publicKey = maybeLoadToken(args.public_key)
    ok = verifySignature(payload, signature, publicKey)
    if args.json:
        emitJson({"ok": True, "mode": "verify", "valid": bool(ok)})
    else:
        print("true" if ok else "false")
    return 0

def cmdEnc(args):
    k, mode = resolveKeyInput(args, require=False, allowModeAuto=False)
    keyMode = 0 if mode == 0 else 333
    chunkBytes = resolveChunkBytes(args.chunk_size, getattr(args, "chunk_bytes", None))
    progress = None if args.json or getattr(args, "no_progress", False) else makeProgress("Encrypting")

    if args.file:
        fp = args.file
        if not Path(fp).exists():
            raise FileNotFoundError(fp)
        validateFileCap(fp, args.no_limit)
        payload = packFilePayload(fp, readBinFile(fp))
        encObj, used = encryptData(payload, k, keyMode=0 if mode == 0 else 1, count=FIXED_COUNT, detached=args.detached, compress=not args.no_compress, chunkSize=chunkBytes, powBits=args.pow_bits, powStart=args.pow_start, progress=progress)
        srcLabel = fp
    else:
        pt = readStdinPayload(args.delim) if args.stdin else args.text
        encObj, used = encryptData(pt, k, keyMode=0 if mode == 0 else 1, count=FIXED_COUNT, detached=args.detached, compress=not args.no_compress, chunkSize=chunkBytes, powBits=args.pow_bits, powStart=args.pow_start, progress=progress)
        srcLabel = "cipher"

    autoKeyOut = None
    if args.write_key:
        writeKeyFile(args.write_key, used)
        autoKeyOut = args.write_key

    if args.detached:
        body = encObj["body"]
        meta = encObj["meta"]
        if args.out:
            bodyPath, metaPath = chooseDetachedOutPaths(srcLabel, args.out)
            writeTextFile(bodyPath, body)
            writeTextFile(metaPath, meta)
            if autoKeyOut is None:
                autoKeyOut = defaultKeyOutPath(bodyPath)
                writeKeyFile(autoKeyOut, used)
            if args.json:
                emitJson({"ok": True, "mode": "enc", "detached": True, "body_out": bodyPath, "meta_out": metaPath, "key": used, "key_out": autoKeyOut, "chunk_bytes": chunkBytes})
            else:
                print(bodyPath)
                print(metaPath)
                print(autoKeyOut)
                if not args.quiet_key:
                    print(used)
            return 0
        if args.json:
            emitJson({"ok": True, "mode": "enc", "detached": True, "body": body, "meta": meta, "key": used, "chunk_bytes": chunkBytes})
        else:
            print(f"meta={meta}")
            print(f"body={body}")
            if not args.quiet_key:
                print(used)
        return 0

    cipher = encObj
    if args.out or args.file:
        outPath = chooseTextOutPath(args.out, defaultName="cipher.sh32") if args.out else defaultEncOutPath(srcLabel)
        writeTextFile(outPath, cipher)
        if autoKeyOut is None:
            autoKeyOut = defaultKeyOutPath(outPath)
            writeKeyFile(autoKeyOut, used)
        if args.json:
            emitJson({"ok": True, "mode": "enc", "detached": False, "out": outPath, "key": used, "key_out": autoKeyOut, "chunk_bytes": chunkBytes})
        else:
            print(outPath)
            print(autoKeyOut)
            if not args.quiet_key:
                print(used)
        return 0

    if args.json:
        emitJson({"ok": True, "mode": "enc", "detached": False, "cipher": cipher, "key": used, "chunk_bytes": chunkBytes})
    else:
        print(cipher)
        if not args.quiet_key:
            print(used)
    return 0

def cmdDec(args):
    k, mode = resolveKeyInput(args, require=True, allowModeAuto=True)
    keyMode = None if mode is None else (0 if mode == 0 else 1)
    progress = None if args.json or getattr(args, "no_progress", False) else makeProgress("Decrypting")

    if args.body is not None or args.meta is not None:
        if args.body is None or args.meta is None:
            raise ValueError("Provide both --body and --meta for detached decryption.")
        body = maybeLoadToken(args.body)
        meta = maybeLoadToken(args.meta)
        pt = decryptData(body, k, keyMode=keyMode, count=FIXED_COUNT, meta=meta, progress=progress)
        srcPath = "detached"
    elif args.file:
        fp = args.file
        if not Path(fp).exists():
            raise FileNotFoundError(fp)
        token = readTextFile(fp).strip()
        pt = decryptData(token, k, keyMode=keyMode, count=FIXED_COUNT, progress=progress)
        srcPath = fp
    else:
        token = readStdinPayload(args.delim).strip() if args.stdin else args.text.strip()
        pt = decryptData(token, k, keyMode=keyMode, count=FIXED_COUNT, progress=progress)
        srcPath = "token"

    unpacked = None if args.as_text else unpackFilePayload(pt)
    if unpacked and not args.as_text:
        restoredName, raw = unpacked
        outPath = chooseDecOutPath(srcPath, restoredName, args.out)
        writeBinFile(outPath, raw)
        if args.json:
            emitJson({"ok": True, "mode": "dec", "out": outPath, "restored_name": restoredName})
        else:
            print(outPath)
        return 0

    if args.out:
        writeTextFile(args.out, pt)
        if args.json:
            emitJson({"ok": True, "mode": "dec", "out": args.out})
        else:
            print(args.out)
        return 0

    if args.json:
        emitJson({"ok": True, "mode": "dec", "text": pt})
    else:
        print(pt)
    return 0

def promptMode(default=0):
    s = input(f"Mode 0=SHEP32, 1=SHEP333 [default {default}]: ").strip()
    return default if s == "" else (0 if int(s) == 0 else 1)

def promptCount(default=8):
    return FIXED_COUNT

def promptChunkUnits(default=1):
    s = input(f"Chunk size units x{CHUNK_UNIT} [default {default}]: ").strip()
    units = default if s == "" else int(s)
    return resolveChunkBytes(units)

def promptKeySource(require=False):
    print("Key source: 1) explicit key  2) phrase  3) key file  4) auto")
    choice = input("> ").strip()
    if choice == "1":
        return sanitizeKeyToken(input("Key: "))
    if choice == "2":
        return input("Phrase: ")
    if choice == "3":
        kp = wizardPickExistingPath(input("Key file path: "), label="Key file")
        return loadKeyFromFile(kp) if kp else None
    if require:
        print("A key source is required.")
        return promptKeySource(require=True)
    return None

def interactiveWizard():
    while True:
        print("SHEP Interactive Menu")
        print("1) Hash")
        print("2) Encrypt")
        print("3) Decrypt")
        print("4) Generate Key")
        print("5) Public Key")
        print("6) Sign")
        print("7) Verify")
        print("8) Range")
        print("9) Benchmark")
        print("0) Exit")
        choice = input("> ").strip()
        try:
            if choice in {"0", "q", "quit", "exit"}:
                return 0
            if choice == "4":
                mode = promptMode(0)
                count = FIXED_COUNT
                kind = input("Source: 1) random  2) text  3) file : ").strip()
                if kind == "2": k = generateKey(input("Text: "), mode, count)
                elif kind == "3":
                    fp = wizardPickExistingPath(input("File path: "), label="File")
                    if not fp: continue
                    k = generateKeyFile(fp, mode, count)
                else: k = generateKey(None, mode, count)
                print(k)
                save = input("Save to key file? (path/blank to skip): ").strip()
                if save:
                    writeKeyFile(save, k)
                    print(f"Wrote {save}", file=sys.stderr)
                continue
            if choice == "1":
                mode = promptMode(0)
                count = FIXED_COUNT
                kind = input("Source: 1) text  2) file : ").strip()
                if kind == "2":
                    fp = wizardPickExistingPath(input("File path: "), label="File")
                    if fp: print(generateKeyFile(fp, mode, count))
                else: print(generateKey(input("Text: "), mode, count))
                continue
            if choice == "2":
                mode = promptMode(0)
                count = FIXED_COUNT
                advanced = input("Advanced options? [y/N]: ").strip().lower() in {"y", "yes"}
                detached = False
                noCompress = False
                chunkBytes = CHUNK_UNIT
                powBits = 0
                powStart = 0
                if advanced:
                    detached = input("Detached output? [y/N]: ").strip().lower() in {"y", "yes"}
                    noCompress = input("Disable compression? [y/N]: ").strip().lower() in {"y", "yes"}
                    chunkBytes = promptChunkUnits(1)
                    x = input("Proof-of-work bits [default 0]: ").strip()
                    powBits = 0 if x == "" else int(x)
                    x = input("Proof-of-work start nonce [default 0]: ").strip()
                    powStart = 0 if x == "" else int(x)
                kind = input("Input type: 1) text  2) file : ").strip()
                k = promptKeySource(require=False)
                progress = makeProgress("Encrypting")
                if kind == "2":
                    fp = wizardPickExistingPath(input("File path: "), label="File")
                    if not fp: continue
                    size = Path(fp).stat().st_size
                    noLimit = False
                    if size > DEFAULT_MAX_BYTES:
                        noLimit = input(f"File is {size} bytes and exceeds the default limit of {DEFAULT_MAX_BYTES}. Override limit? [y/N]: ").strip().lower() in {"y", "yes"}
                    validateFileCap(fp, noLimit)
                    payload = packFilePayload(fp, readBinFile(fp))
                    out, used = encryptData(payload, k, keyMode=mode, count=count, detached=detached, compress=not noCompress, chunkSize=chunkBytes, powBits=powBits, powStart=powStart, progress=progress)
                    if detached:
                        base = input(f"Base output path [default {Path(fp).with_suffix('')}]: ").strip() or str(Path(fp).with_suffix(''))
                        bodyPath = base + ".sh32.body"
                        metaPath = base + ".sh32.meta"
                        writeTextFile(bodyPath, out["body"])
                        writeTextFile(metaPath, out["meta"])
                        keyPath = input(f"Key file path [default {Path(bodyPath).with_suffix('.pkey')}]: ").strip() or str(Path(bodyPath).with_suffix('.pkey'))
                        writeKeyFile(keyPath, used)
                        print(bodyPath)
                        print(metaPath)
                        print(keyPath)
                    else:
                        outPath = input(f"Output path [default {Path(fp).with_suffix('.sh32')}]: ").strip() or str(Path(fp).with_suffix('.sh32'))
                        outPath = chooseTextOutPath(outPath, defaultName=Path(outPath).name)
                        writeTextFile(outPath, out)
                        keyPath = input(f"Key file path [default {Path(outPath).with_suffix('.pkey')}]: ").strip() or str(Path(outPath).with_suffix('.pkey'))
                        writeKeyFile(keyPath, used)
                        print(outPath)
                        print(keyPath)
                else:
                    textIn = input("Plaintext: ")
                    out, used = encryptData(textIn, k, keyMode=mode, count=count, detached=detached, compress=not noCompress, chunkSize=chunkBytes, powBits=powBits, powStart=powStart, progress=progress)
                    save = input("Save ciphertext to .sh32 file? [y/N]: ").strip().lower() in {"y", "yes"}
                    if detached:
                        if save:
                            base = input("Base output path [default cipher]: ").strip() or "cipher"
                            bodyPath = base + ".sh32.body"
                            metaPath = base + ".sh32.meta"
                            writeTextFile(bodyPath, out["body"])
                            writeTextFile(metaPath, out["meta"])
                            keyPath = input(f"Key file path [default {Path(bodyPath).with_suffix('.pkey')}]: ").strip() or str(Path(bodyPath).with_suffix('.pkey'))
                            writeKeyFile(keyPath, used)
                            print(bodyPath)
                            print(metaPath)
                            print(keyPath)
                        else:
                            print(f"meta={out['meta']}")
                            print(f"body={out['body']}")
                            print(used)
                    else:
                        if save:
                            outPath = input("Output path [default cipher.sh32]: ").strip() or "cipher.sh32"
                            outPath = chooseTextOutPath(outPath, defaultName="cipher.sh32")
                            writeTextFile(outPath, out)
                            keyPath = input(f"Key file path [default {Path(outPath).with_suffix('.pkey')}]: ").strip() or str(Path(outPath).with_suffix('.pkey'))
                            writeKeyFile(keyPath, used)
                            print(outPath)
                            print(keyPath)
                        else:
                            print(out)
                            print(used)
                continue
            if choice == "3":
                modeText = input("Mode 0=SHEP32, 1=SHEP333, blank=auto: ").strip()
                mode = None if modeText == "" else (0 if int(modeText) == 0 else 1)
                count = FIXED_COUNT
                advanced = input("Advanced options? [y/N]: ").strip().lower() in {"y", "yes"}
                asText = False
                detachedIn = False
                if advanced:
                    asText = input("Treat output as text only? [y/N]: ").strip().lower() in {"y", "yes"}
                    detachedIn = input("Detached input? [y/N]: ").strip().lower() in {"y", "yes"}
                kind = input("Input type: 1) text  2) file : ").strip()
                k = promptKeySource(require=True)
                progress = makeProgress("Decrypting")
                if detachedIn:
                    if kind == "2":
                        bodyPath = wizardPickExistingPath(input("Body file path: "), label="Body file")
                        metaPath = wizardPickExistingPath(input("Meta file path: "), label="Meta file")
                        if not bodyPath or not metaPath: continue
                        body = readTextFile(bodyPath).strip()
                        meta = readTextFile(metaPath).strip()
                    else:
                        body = maybeLoadToken(input("Body token: ").strip())
                        meta = maybeLoadToken(input("Meta token: ").strip())
                    pt = decryptData(body, k, keyMode=mode, count=count, meta=meta, progress=progress)
                else:
                    if kind == "2":
                        fp = wizardPickExistingPath(input("Token file path: "), label="Cipher file")
                        if not fp: continue
                        token = readTextFile(fp).strip()
                    else:
                        token = input("Ciphertext token: ").strip()
                    pt = decryptData(token, k, keyMode=mode, count=count, progress=progress)
                unpacked = None if asText else unpackFilePayload(pt)
                if unpacked and not asText:
                    restoredName, raw = unpacked
                    outPath = input(f"Restore output path [default {restoredName}]: ").strip() or restoredName
                    writeBinFile(outPath, raw)
                    print(outPath)
                else:
                    saveText = input("Save plaintext to file? [y/N]: ").strip().lower() in {"y", "yes"}
                    if saveText:
                        outPath = input("Output path [default plain.txt]: ").strip() or "plain.txt"
                        writeTextFile(outPath, pt)
                        print(outPath)
                    else:
                        print(pt)
                continue
            if choice == "5":
                mode = promptMode(0)
                count = FIXED_COUNT
                k = promptKeySource(require=True)
                print(generatePublicKey(k, 0 if mode == 0 else 333, count))
                continue
            if choice == "6":
                mode = promptMode(0)
                count = FIXED_COUNT
                k = promptKeySource(require=True)
                text = input("Text to sign: ")
                sig = signData(text, k, 0 if mode == 0 else 333, count)
                print(f"signature={sig['signature']}")
                print(f"publicKey={sig['publicKey']}")
                continue
            if choice == "7":
                text = input("Text to verify: ")
                sig = input("Signature token: ").strip()
                pub = input("Public key token: ").strip()
                print("true" if verifySignature(text, maybeLoadToken(sig), maybeLoadToken(pub)) else "false")
                continue
            if choice == "8":
                mode = promptMode(0)
                count = FIXED_COUNT
                start = int(input("Start integer: ").strip())
                hashes = int(input("How many hashes: ").strip())
                bare = input("Bare hashes only? [y/N]: ").strip().lower() in {"y", "yes"}
                for line in generateHashRange(start, hashes, mode, count, bare=bare):
                    print(line)
                continue
            if choice == "9":
                mode = promptMode(0)
                count = FIXED_COUNT
                benchType = input("Benchmark type: 1) speed  2) speed + diffusion report [default 1]: ").strip() or "1"
                randomInputs = input("Use random inputs? [Y/n]: ").strip().lower() not in {"n", "no"}
                hashes = int((input("How many inputs / hashes [default 1000]: ").strip() or "1000"))
                inputBits = int((input("Input bits [default 256]: ").strip() or "256"))
                start = None
                if not randomInputs:
                    start = int((input("Start integer [default 0]: ").strip() or "0"))
                save = input("Save benchmark report to file? [y/N]: ").strip().lower() in {"y", "yes"}
                out = None
                if save:
                    out = input("Output path [default bench.tsv]: ").strip() or "bench.tsv"
                showProgress = input("Show progress? [Y/n]: ").strip().lower() not in {"n", "no"}
                benchRange(start, hashes, mode, count, randomInputs=randomInputs, inputBits=inputBits, compare=(benchType == "2"), out=out, showProgress=showProgress)
                continue
            printErr("Unknown selection.")
        except Exception as e:
            printErr(str(e))
    return 0

def buildParser():
    parser = argparse.ArgumentParser(
        prog="shep32",
        description="SHEP CLI — SHEP32 primary keys and SHEP333 extended keys",
        epilog=(
            "Common examples:\n"
            "  shep32 key\n"
            "  shep32 hash --text \"hello\"\n"
            "  shep32 hash --mode 1 --text \"hello\"\n"
            "  shep32 enc --text \"secret\" --key \"<shep32-key>\"\n"
            "  shep32 enc --text \"secret\" --key \"<shep333-key>\" --mode 1\n"
            "  shep32 enc --text \"secret\" --phrase \"1234\" --mode 1\n"
            "  shep32 dec --text \"<token>\" --key \"<shep32-key>\"\n"
            "  shep32 dec --text \"<token>\" --phrase \"1234\" --mode 1\n"
            "  shep32 pubkey --key \"<shep333-key>\" --mode 1\n"
            "  shep32 sign --text \"message\" --phrase \"1234\" --mode 1"
        ),
        formatter_class=CliFmt,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {CLI_VERSION}")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("start", help="Open the interactive menu")

    def addModeArgs(p, default=0, allowAuto=False):
        p.add_argument("--mode", type=int, default=(None if allowAuto else default), help="0 = SHEP32 primary, 1 = SHEP333 extended")
        p.add_argument("--direct-bits", dest="direct_bits", type=int, default=256, help=argparse.SUPPRESS)
        p.add_argument("--lane-bits", dest="lane_bits", type=int, default=336, help=argparse.SUPPRESS)
        p.add_argument("--block-bytes", dest="block_bytes", type=int, default=4096, help=argparse.SUPPRESS)

    def addChunkArgs(p):
        p.add_argument("--chunk-size", dest="chunk_size", type=int, default=1, help=f"Chunk units of {CHUNK_UNIT} bytes (default 1)")
        p.add_argument("--chunk-bytes", dest="chunk_bytes", type=int, default=None, help="Exact chunk size in bytes")

    def addKeyInputArgs(p, require=False, allowAutoMode=False):
        kg = p.add_mutually_exclusive_group(required=require)
        kg.add_argument("--key", default=None, help="Explicit SHEP32 or SHEP333 key")
        kg.add_argument("--phrase", "-p", default=None, help="Explicit phrase, even if it looks like a key")
        kg.add_argument("--keyfile", default=None, help="File containing an explicit SHEP32 or SHEP333 key")
        addModeArgs(p, default=0, allowAuto=allowAutoMode)
        p.epilog = keyInputHelp()

    pk = sub.add_parser("key", help="Generate a fresh random key or derive one from text, file, or phrase input", formatter_class=CliFmt)
    g = pk.add_mutually_exclusive_group(required=False)
    g.add_argument("--text", default=None)
    g.add_argument("--file", default=None)
    g.add_argument("--phrase", "-p", default=None)
    addModeArgs(pk)
    pk.add_argument("--save", default=None)
    pk.add_argument("--json", action="store_true")

    ph = sub.add_parser("hash", help="Deterministically derive a SHEP32 or SHEP333 key from text or file input", formatter_class=CliFmt)
    g = ph.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", default=None)
    g.add_argument("--file", default=None)
    addModeArgs(ph)
    ph.add_argument("--json", action="store_true")

    pr = sub.add_parser("range", help="Generate a range of SHEP32 or SHEP333 keys from a starting integer", formatter_class=CliFmt)
    pr.add_argument("--start", type=int, required=True)
    pr.add_argument("--hashes", type=int, required=True)
    addModeArgs(pr)
    pr.add_argument("--out", default=None)
    pr.add_argument("--bare", action="store_true")
    pr.add_argument("--progress", action="store_true")

    pb = sub.add_parser("bench", help="Benchmark key generation speed, save individual hashes, and optionally run a diffusion report", formatter_class=CliFmt)
    pb.add_argument("--start", type=int, default=None)
    pb.add_argument("--hashes", type=int, required=True)
    pb.add_argument("--random-inputs", dest="random_inputs", action="store_true", default=None)
    pb.add_argument("--sequential", dest="random_inputs", action="store_false")
    pb.add_argument("--input-bits", dest="input_bits", type=int, default=256)
    pb.add_argument("--compare", action="store_true")
    pb.add_argument("--bits", default=None, help="Compare this many bit positions, or 'all'")
    pb.add_argument("--out", default=None)
    pb.add_argument("--hashes-out", dest="hashes_out", default=None, help="Write individual input/hash pairs here; defaults to hashes{parameters}.txt")
    pb.add_argument("--no-progress", dest="no_progress", action="store_true")
    addModeArgs(pb)

    pp = sub.add_parser("pair", help="Show the two internal 256-bit encryption keys derived from a key or text/file source", formatter_class=CliFmt)
    g = pp.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", default=None)
    g.add_argument("--file", default=None)
    addModeArgs(pp)
    pp.add_argument("--json", action="store_true")

    pe = sub.add_parser("enc", help="Encrypt text or a file into a .sh32 token", formatter_class=CliFmt)
    g = pe.add_mutually_exclusive_group(required=True)
    g.add_argument("-f", "--file", dest="file", default=None)
    g.add_argument("--text", dest="text", default=None)
    g.add_argument("-e", dest="text", default=None)
    g.add_argument("--stdin", action="store_true")
    pe.add_argument("--delim", default=None)
    addKeyInputArgs(pe, require=False, allowAutoMode=False)
    pe.add_argument("--detached", action="store_true")
    pe.add_argument("--no-compress", dest="no_compress", action="store_true")
    addChunkArgs(pe)
    pe.add_argument("--pow-bits", dest="pow_bits", type=int, default=0)
    pe.add_argument("--pow-start", dest="pow_start", default=0)
    pe.add_argument("-o", "--out", default=None)
    pe.add_argument("--no-limit", dest="no_limit", action="store_true")
    pe.add_argument("--quiet-key", dest="quiet_key", action="store_true")
    pe.add_argument("--write-key", dest="write_key", default=None)
    pe.add_argument("--no-progress", dest="no_progress", action="store_true")
    pe.add_argument("--json", action="store_true")

    pd = sub.add_parser("dec", help="Decrypt a .sh32 token, detached body/meta tokens, or a token file", formatter_class=CliFmt)
    g = pd.add_mutually_exclusive_group(required=False)
    g.add_argument("-f", "--file", dest="file", default=None)
    g.add_argument("--text", dest="text", default=None)
    g.add_argument("-d", dest="text", default=None)
    g.add_argument("--stdin", action="store_true")
    pd.add_argument("--body", default=None)
    pd.add_argument("--meta", default=None)
    pd.add_argument("--delim", default=None)
    addKeyInputArgs(pd, require=True, allowAutoMode=True)
    pd.add_argument("-o", "--out", default=None)
    pd.add_argument("--as-text", dest="as_text", action="store_true")
    pd.add_argument("--no-progress", dest="no_progress", action="store_true")
    pd.add_argument("--json", action="store_true")

    pg = sub.add_parser("pubkey", help="Derive an Ed25519 public key from a SHEP key source", formatter_class=CliFmt)
    addKeyInputArgs(pg, require=True, allowAutoMode=False)
    pg.add_argument("--json", action="store_true")

    ps = sub.add_parser("sign", help="Sign text or file contents with the Ed25519 key derived from a SHEP key source", formatter_class=CliFmt)
    g = ps.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", default=None)
    g.add_argument("-f", "--file", dest="file", default=None)
    g.add_argument("--stdin", action="store_true")
    ps.add_argument("--delim", default=None)
    addKeyInputArgs(ps, require=True, allowAutoMode=False)
    ps.add_argument("--json", action="store_true")

    pv = sub.add_parser("verify", help="Verify text or file contents with a signature and public key", formatter_class=CliFmt)
    g = pv.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", default=None)
    g.add_argument("-f", "--file", dest="file", default=None)
    g.add_argument("--stdin", action="store_true")
    pv.add_argument("--delim", default=None)
    pv.add_argument("--signature", required=True)
    pv.add_argument("--public-key", dest="public_key", required=True)
    pv.add_argument("--json", action="store_true")
    return parser

def main(argv=None):
    parser = buildParser()
    args = parser.parse_args(argv)
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
        if args.cmd == "hash":
            return cmdHash(args)
        if args.cmd == "range":
            return cmdRange(args)
        if args.cmd == "bench":
            return cmdBench(args)
        if args.cmd == "pair":
            return cmdPair(args)
        if args.cmd == "enc":
            return cmdEnc(args)
        if args.cmd == "dec":
            return cmdDec(args)
        if args.cmd == "pubkey":
            return cmdPubKey(args)
        if args.cmd == "sign":
            return cmdSign(args)
        if args.cmd == "verify":
            return cmdVerify(args)
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
