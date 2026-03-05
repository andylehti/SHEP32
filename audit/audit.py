import math, hashlib, random, zlib

# =============================================================================
# OPTIONAL: AES (pycryptodome or cryptography)
# =============================================================================
aesOk = False
aesBackend = None
try:
    from Crypto.Cipher import AES as cdaes
    aesOk = True
    aesBackend = "pycryptodome"
except Exception:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as crcipher
        from cryptography.hazmat.primitives.ciphers.algorithms import AES as craes
        from cryptography.hazmat.primitives.ciphers.modes import ECB as crECB
        aesOk = True
        aesBackend = "cryptography"
    except Exception:
        pass

# =============================================================================
# CORE CONSTANTS / HELPERS
# =============================================================================
hexch = "0123456789abcdef"
hexmap = {c: i for i, c in enumerate(hexch)}

def u8(s):
    return s.encode("utf-8", errors="surrogatepass")

def toHex64(h):
    h = (h or "").strip().lower()
    for c in h:
        if c not in hexmap:
            h = hashlib.sha256(u8(h)).hexdigest()
            break
    if len(h) < 64:
        h = h.ljust(64, "0")
    if len(h) > 64:
        h = h[:64]
    return h

def bytesHex64(b):
    return toHex64((b or b"").hex())

# =============================================================================
# INPUT GENERATION MODES (MODE=1 WRAPS UNICODE RANGE)
# =============================================================================
def getInput(mode, state):
    if mode == 0:
        pool = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(random.choice(pool) for _ in range(random.randint(5, 50))), state
    if mode == 1:
        maxcp = 0x110000
        out = []
        x = state
        while len(out) < 32:
            if x >= maxcp:
                x = 0
            if not (0xD800 <= x <= 0xDFFF):
                out.append(chr(x))
            x += 1
        return "".join(out), x
    return str(state), state + 1

# =============================================================================
# POSITIONAL MATRIX DISTRIBUTION
# =============================================================================
def positionalDistribution(strings, matrix=None):
    if strings is None:
        strings = []
    if isinstance(strings, (str, bytes)):
        strings = [strings]
    if matrix is None:
        matrix = {"counts": [], "alphabet": {}, "total": 0, "positions": 0}
    if not isinstance(matrix, dict) or "counts" not in matrix or "alphabet" not in matrix:
        raise ValueError("matrix must be a dict like {'counts': [], 'alphabet': {}, 'total': 0, 'positions': 0}")
    counts = matrix["counts"]
    alphabet = matrix["alphabet"]
    positions = int(matrix.get("positions", 0))

    def ensurePos(n):
        nonlocal positions
        if n <= positions:
            return
        add = n - positions
        for r in range(len(counts)):
            counts[r].extend([0] * add)
        positions = n

    def ensureRows(n):
        cur = len(counts)
        if n <= cur:
            return
        for _ in range(n - cur):
            counts.append([0] * positions)

    for s in strings:
        if s is None:
            continue
        if isinstance(s, bytes):
            s = s.decode("utf-8", "replace")
        else:
            s = str(s)
        if not s:
            continue
        ensurePos(len(s))
        for i, ch in enumerate(s):
            r = alphabet.get(ch)
            if r is None:
                r = len(alphabet)
                alphabet[ch] = r
                ensureRows(r + 1)
            counts[r][i] += 1
        matrix["total"] = int(matrix.get("total", 0)) + 1

    invAlphabet = [None] * len(alphabet)
    for ch, r in alphabet.items():
        invAlphabet[r] = ch
    matrix["positions"] = positions

    return {
        "counts": counts,
        "alphabet": alphabet,
        "invAlphabet": invAlphabet,
        "positions": positions,
        "unique": len(alphabet),
        "total": int(matrix.get("total", 0)),
    }

def distributionScore(pm, positions=None, totalStrings=None):
    counts = pm["counts"]
    alphabet = pm.get("alphabet", None)

    if totalStrings is None:
        totalStrings = int(pm.get("total", 0))
    totalStrings = int(totalStrings)

    unique = int(pm.get("unique", 0))
    if unique <= 0:
        unique = len(counts)
    if unique <= 0 or totalStrings <= 0:
        raise ValueError("unique and totalStrings must be > 0")
    if len(counts) != unique:
        unique = len(counts)
    if unique == 0:
        raise ValueError("empty counts")

    if positions is None:
        positions = int(pm.get("positions", 0))
        if positions <= 0:
            m = 0
            for r in range(unique):
                if len(counts[r]) > m:
                    m = len(counts[r])
            positions = m
    positions = int(positions)
    if positions <= 0:
        raise ValueError("positions must be > 0")
    for r in range(unique):
        if len(counts[r]) < positions:
            raise ValueError("counts rows must have at least 'positions' columns")
    if alphabet is not None and isinstance(alphabet, dict):
        if len(alphabet) != unique:
            unique = len(alphabet)

    formulaA = positions * unique
    formulaB = positions * totalStrings

    ideal = totalStrings / unique
    low = totalStrings // unique
    high = low + 1
    needHigh = totalStrings - low * unique

    deviation = 0
    for c in range(positions):
        col = [counts[r][c] for r in range(unique)]
        col.sort(reverse=True)
        if needHigh == 0:
            for v in col:
                d = v - low
                deviation += d if d >= 0 else -d
        else:
            for i, v in enumerate(col):
                t = high if i < needHigh else low
                d = v - t
                deviation += d if d >= 0 else -d

    penalty = deviation / formulaB
    score = 1.0 - penalty

    return {
        "formulaA": formulaA,
        "formulaB": formulaB,
        "idealPerCell": ideal,
        "lowTarget": low,
        "highTarget": high,
        "needHighPerPos": needHigh,
        "deviation": deviation,
        "penalty": penalty,
        "score": score
    }

# =============================================================================
# WEAK / BAD EXAMPLES
# =============================================================================
def rc4Bytes(keyBytes, dataBytes):
    S = list(range(256))
    j = 0
    klen = len(keyBytes) or 1
    for i in range(256):
        j = (j + S[i] + keyBytes[i % klen]) & 255
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    out = bytearray()
    for byte in dataBytes:
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 255]
        out.append(byte ^ K)
    return bytes(out)

def xorRep(keyBytes, dataBytes):
    klen = len(keyBytes) or 1
    return bytes((b ^ keyBytes[i % klen]) for i, b in enumerate(dataBytes))

def lcgStream(seedValue, nbytes):
    x = seedValue & 0xFFFFFFFF
    out = bytearray()
    for _ in range(nbytes):
        x = (1664525 * x + 1013904223) & 0xFFFFFFFF
        out.append((x >> 24) & 0xFF)
    return bytes(out)

# =============================================================================
# AES ECB
# =============================================================================
aesKey = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

def aesEcb(dataBytes):
    pad = 16 - (len(dataBytes) % 16)
    data = dataBytes + bytes([pad]) * pad
    if aesBackend == "pycryptodome":
        c = cdaes.new(aesKey, cdaes.MODE_ECB)
        return c.encrypt(data)
    if aesBackend == "cryptography":
        enc = crcipher(craes(aesKey), crECB()).encryptor()
        return enc.update(data) + enc.finalize()
    return None

# =============================================================================
# CANDIDATE GENERATORS
# =============================================================================
def sha256Hex(s): return hashlib.sha256(u8(s)).hexdigest()
def sha3Hex(s): return hashlib.sha3_256(u8(s)).hexdigest()
def blake2bHex(s): return hashlib.blake2b(u8(s), digest_size=32).hexdigest()
def blake2sHex(s): return hashlib.blake2s(u8(s), digest_size=32).hexdigest()
def sha512tHex(s): return hashlib.sha512(u8(s)).hexdigest()[:64]
def md5Hex(s): return hashlib.md5(u8(s)).hexdigest().ljust(64, "0")
def sha1Hex(s): return hashlib.sha1(u8(s)).hexdigest().ljust(64, "0")

def crc32Hex(s):
    v = zlib.crc32(u8(s)) & 0xFFFFFFFF
    return toHex64(f"{v:08x}")

def adler32Hex(s):
    v = zlib.adler32(u8(s)) & 0xFFFFFFFF
    return toHex64(f"{v:08x}")

rc4Key = bytes.fromhex("00112233445566778899aabbccddeeff")
xorKey = bytes.fromhex("deadbeefcafebabe")

def rc4Hex(s): return bytesHex64(rc4Bytes(rc4Key, u8(s))[:32])
def xorHex(s): return bytesHex64(xorRep(xorKey, u8(s))[:32])

def lcgHex(s):
    seedValue = int.from_bytes(hashlib.md5(u8(s)).digest()[:4], "big")
    return bytesHex64(lcgStream(seedValue, 32))

def aesHex(s): return bytesHex64(aesEcb(u8(s))[:32])
def shepHex(s): return generatePKey(s)

def buildCandidates():
    c = [
        ("SHA256", sha256Hex),
        ("SHA3_256", sha3Hex),
        ("BLAKE2b", blake2bHex),
        ("BLAKE2s", blake2sHex),
        ("SHA512t", sha512tHex),
    ]
    if aesOk:
        c.append(("AES_ECB", aesHex))
    c += [
        ("RC4", rc4Hex),
        ("MD5", md5Hex),
        ("SHA1", sha1Hex),
        ("XORRep", xorHex),
        ("CRC32", crc32Hex),
        ("ADLER32", adler32Hex),
        ("LCG32", lcgHex),
        ("SHEP32", shepHex),
    ]
    return c

# =============================================================================
# METRICS
# =============================================================================
def entropyNib(counts, total):
    if total <= 0:
        return 0.0
    e = 0.0
    for c in counts:
        if c:
            p = c / total
            e -= p * math.log(p, 2)
    return e

def chiSquare(counts, total, k=16):
    if total <= 0:
        return 0.0
    exp = total / k
    if exp == 0:
        return 0.0
    x2 = 0.0
    for c in counts:
        d = c - exp
        x2 += (d * d) / exp
    return x2

def chiSquareScore(counts, total, k=16):
    if total <= 0:
        return 0.0

    exp = total / k
    if exp <= 0:
        return 0.0

    x2 = 0.0
    for c in counts:
        d = c - exp
        x2 += (d * d) / exp

    dof = k - 1
    if dof <= 0:
        return 0.0

    a = 2.0 / (9.0 * dof)
    z = ((x2 / dof) ** (1.0 / 3.0) - (1.0 - a)) / math.sqrt(a)

    # right-tail p-value: p = 1 - Phi(z) = 0.5 * erfc(z / sqrt(2))
    p = 0.5 * math.erfc(z / math.sqrt(2.0))

    if p < 0.0:
        p = 0.0
    if p > 1.0:
        p = 1.0
    return p

def runsScore(hexStr):
    bits = []
    for ch in hexStr:
        v = hexmap[ch]
        bits += [(v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1]

    n = len(bits)
    if n < 2:
        return 0.0

    runs = 1
    n1 = 0
    for i in range(n):
        if bits[i] == 1:
            n1 += 1
        if i > 0 and bits[i] != bits[i - 1]:
            runs += 1
    n0 = n - n1

    if n0 == 0 or n1 == 0:
        return 0.0

    exp = (2.0 * n1 * n0) / n + 1.0
    var = (2.0 * n1 * n0 * (2.0 * n1 * n0 - n)) / (n * n * (n - 1))
    if var <= 0.0:
        return 0.0

    z = (runs - exp) / math.sqrt(var)

    # two-sided p-value for runs test
    p = math.erfc(abs(z) / math.sqrt(2.0))

    if p < 0.0:
        p = 0.0
    if p > 1.0:
        p = 1.0
    return p

def hamPrev(hexStr, prevHex):
    if not prevHex:
        return 0.5
    d = 0
    for a, b in zip(hexStr, prevHex):
        x = hexmap[a] ^ hexmap[b]
        d += (x & 1) + ((x >> 1) & 1) + ((x >> 2) & 1) + ((x >> 3) & 1)
    return 1.0 - (abs(d - 128) / 128.0)

def bal07(counts):
    a = sum(counts[:8])
    b = sum(counts[8:])
    t = a + b
    if t == 0:
        return 0.0
    return 1.0 - (abs(a - b) / t)

def posDev(matrix64x16, totalPerPos):
    if totalPerPos <= 0:
        return 1.0
    target = totalPerPos / 16.0
    worst = 0.0
    for pos in range(64):
        row = matrix64x16[pos]
        for c in row:
            worst = max(worst, abs(c - target) / target)
    return 1.0 / (1.0 + worst)

def miScore(pairCounts):
    total = 0
    row = [0] * 16
    col = [0] * 16
    for i in range(16):
        for j in range(16):
            v = pairCounts[i][j]
            total += v
            row[i] += v
            col[j] += v
    if total == 0:
        return 1.0
    mi = 0.0
    for i in range(16):
        for j in range(16):
            v = pairCounts[i][j]
            if v == 0:
                continue
            pxy = v / total
            px = row[i] / total
            py = col[j] / total
            mi += pxy * math.log(pxy / (px * py), 2)
    return 1.0 / (1.0 + mi)

def weightedScore01(values9, cfg):
    keys = ["entropy","chi","runs","hamming","balance","positional","mi","variance","distribution"]
    wsum = 0.0
    s = 0.0
    for i, k in enumerate(keys):
        inc, w = cfg.get(k, [0, 0])
        if inc:
            w = float(w)
            if w > 0.0:
                wsum += w
                s += float(values9[i]) * w
    if wsum <= 0.0:
        return 0.0
    v = s / wsum
    if v < 0.0: v = 0.0
    if v > 1.0: v = 1.0
    return v

# =============================================================================
# SCORE HELPERS
# =============================================================================
def maxNorm(vals):
    m = max(vals)
    if m == 0:
        return [0.0] * len(vals)
    return [v / m for v in vals]

def roundRatios(scores):
    m = max(scores)
    if m == 0:
        return [0.0] * len(scores)
    return [s / m for s in scores]

# =============================================================================
# PACK METRIC HELPERS + TABLE HEADER
# =============================================================================
def initPackMetricSums():
    return [0.0] * 9

def addPackMetricSums(dst, src):
    for i in range(9):
        dst[i] += src[i]

def divPackMetricSums(sums, n):
    if n <= 0:
        return [0.0] * 9
    return [v / n for v in sums]

# =============================================================================
# STATS INIT / UPDATES
# =============================================================================
def initStats(name):
    return {
        "name": name,
        "count": 0,
        "prevHex": None,
        "matrix": [[0] * 16 for _ in range(64)],
        "pairCounts": [[0] * 16 for _ in range(16)],
        "pmMatrix": {"counts": [], "alphabet": {}, "total": 0, "positions": 0},
        "packRaw": 0.0,
        "packNorm": 0.0,
        "cumRaw": 0.0,
        "cumNorm": 0.0,
        "packMetricSumsN": initPackMetricSums(),
        "packMetricSumsR": initPackMetricSums(),
    }

def resetAlgo(st):
    st["count"] = 0
    st["prevHex"] = None
    st["matrix"] = [[0] * 16 for _ in range(64)]
    st["pairCounts"] = [[0] * 16 for _ in range(16)]
    st["pmMatrix"] = {"counts": [], "alphabet": {}, "total": 0, "positions": 0}

def updateFreq(st, hexStr):
    for pos, ch in enumerate(hexStr):
        st["matrix"][pos][hexmap[ch]] += 1

def updateTran(st, hexStr):
    for a, b in zip(hexStr, hexStr[1:]):
        st["pairCounts"][hexmap[a]][hexmap[b]] += 1

# =============================================================================
# TSV LOGGING
# =============================================================================
def tsvHead(fp, names):
    cols = ["iter", "pack", "inputLen"]
    if rawScores:
        for n in names:
            cols += [n + "Raw", n + "RawRatio"]
    if normalizedScores:
        for n in names:
            cols += [n + "Norm", n + "NormRatio"]
    fp.write("\t".join(cols) + "\n")

def tsvFull(fp):
    cols = [
        "iter","pack","inputLen","inputPreview","cand",
        "ent","chiScore","runs","ham","bal","pos","mi","var","pmScore","chiRaw",
        "rawScore","rawRatio","normScore","normRatio"
    ]
    fp.write("\t".join(cols) + "\n")

def tsvRow(fp, row):
    fp.write("\t".join(str(x) for x in row) + "\n")

# =============================================================================
# PRINTING
# =============================================================================
def fmt(s, w):
    s = str(s)
    return s[:w] if len(s) > w else s + (" " * (w - len(s)))

def showScores(vals, decimals=1):
    q = 10 ** int(decimals)
    out = []
    for v in vals:
        out.append(str(round(v * q) / q))
    return "[" + ",".join(out) + "]"

def scoreLegend(names):
    parts = []
    for i, n in enumerate(names, start=1):
        parts.append(f"score{i}={n}")
    print("LEGEND:", " | ".join(parts))

def printHeader(names):
    base = ["ITER","PACK","MASTER_R","MASTER_N"]
    cols = base + (["score"] if showAllScores else [])
    if not showAllScores:
        for n in names:
            if rawScores:
                cols.append(n + "_R")
            if normalizedScores:
                cols.append(n + "_N")
    widths = [6,6,10,10]
    if showAllScores:
        widths += [120]
    else:
        widths += [10] * (len(cols) - 4)
    line = " | ".join(fmt(c, w) for c, w in zip(cols, widths))
    bar = "-" * len(line)
    print(bar)
    print(line)
    print(bar)
    return widths

def printRow(cols, widths):
    print(" | ".join(fmt(c, w) for c, w in zip(cols, widths)))


def printMetricLegend():
    print("entropy (E), chi randomness (C), runs (R), hamming (H), balance (B), positional (P), transition MI (M), variance (V), distribution (D)")

def printHeaderWithMetricCells(names):
    base = ["ITER", "PACK", "MASTER_R", "MASTER_N"]
    cols = base[:]

    absReady = printAbs and rawScores and normalizedScores and (normalizedScores or printActNorm or printActCumNorm)

    for n in names:
        if rawScores:
            cols.append(n + "_R")
        if normalizedScores:
            cols.append(n + "_N")

        if printAct:
            cols.append("Act")
        if printActNorm:
            cols.append("ActN")
        if printActCum:
            cols.append("ActCum")
        if printActCumNorm:
            cols.append("ActCumN")

        if absReady:
            cols.append("Abs")

        cols.append(metricHeaderText())

    widths = [6, 6, 10, 10]
    mW = metricColWidth()

    for _ in names:
        if rawScores:
            widths.append(10)
        if normalizedScores:
            widths.append(10)

        if printAct:
            widths.append(6)
        if printActNorm:
            widths.append(6)
        if printActCum:
            widths.append(7)
        if printActCumNorm:
            widths.append(8)

        if absReady:
            widths.append(6)

        widths.append(mW)

    line = " | ".join(fmt(c, w) for c, w in zip(cols, widths))
    bar = "-" * len(line)
    print(bar)
    print(line)
    print(bar)
    return widths

# =============================================================================
# SCORE DISPLAY
# =============================================================================
def fmtPct01(x):
    if x is None:
        x = 0.0
    if x < 0.0:
        x = 0.0
    if x > 0.999:
        x = 0.999
    return f"{x*100:04.1f}"

def metricsCell9(m):
    return f"{fmtPct01(m[0])}, {fmtPct01(m[1])}, {fmtPct01(m[2])}, {fmtPct01(m[3])}, {fmtPct01(m[4])}, {fmtPct01(m[5])}, {fmtPct01(m[6])}, {fmtPct01(m[7])}, {fmtPct01(m[8])}"

def metricColWidth():
    return 52

def metricHeaderText():
    return "E     C     R     H     B     P     M     V     D".ljust(metricColWidth())

# =============================================================================
# MAIN RUNNER
# =============================================================================

def pMid(p):
    if p is None:
        return 0.0
    try:
        p = float(p)
    except Exception:
        return 0.0
    if p < 0.0:
        p = 0.0
    if p > 1.0:
        p = 1.0
    return max(0.0, 1.0 - 4.0 * (p - 0.5) * (p - 0.5))

def runCompare():
    if not rawScores and not normalizedScores and not printAct and not printActNorm and not printActCum and not printActCumNorm and not printAbs:
        return

    random.seed(seed)

    candList = buildCandidates()
    names = [n for n, _ in candList]
    funcs = [f for _, f in candList]
    stats = [initStats(n) for n in names]

    printMetricLegend()
    widths = printHeaderWithMetricCells(names)

    masterRaw = 0.0
    masterNorm = 0.0
    packMasterRaw = 0.0
    packMasterNorm = 0.0

    packCount = 0
    packStartIter = 1

    actCumSum = [0.0] * len(names)
    actCumSumNorm = [0.0] * len(names)

    packActSum = [0.0] * len(names)
    packActSumNorm = [0.0] * len(names)

    totalPackRaw = [0.0] * len(names)
    totalPackNorm = [0.0] * len(names)

    state = 0

    fp = open(tsvPath, "w", encoding="utf-8")
    if lightLog:
        tsvHead(fp, names)
    else:
        tsvFull(fp)

    needNorm = normalizedScores or printActNorm or printActCumNorm or printAbs

    for i in range(1, iters + 1):
        packIndex = (i - 1) // packSize + 1

        inputStr, state = getInput(mode, state)
        inputLen = len(inputStr)
        preview = inputStr[:previewLen].replace("\t", " ").replace("\n", " ")

        mets = []
        for idx, fn in enumerate(funcs):
            hx = toHex64(fn(inputStr))
            st = stats[idx]

            updateFreq(st, hx)
            updateTran(st, hx)

            pm = positionalDistribution(hx, st["pmMatrix"])
            pmScore = distributionScore(pm, positions=64, totalStrings=st["count"] + 1)["score"]

            counts = [0] * 16
            for ch in hx:
                counts[hexmap[ch]] += 1

            ent = entropyNib(counts, 64) / 4.0

            chiP = chiSquareScore(counts, 64)
            chiRaw = chiSquare(counts, 64)
            runsP = runsScore(hx)

            chiUse = pMid(chiP)
            runsUse = pMid(runsP)

            ham = hamPrev(hx, st["prevHex"])
            bal = bal07(counts)
            totalPerPos = st["count"] + 1
            pos = posDev(st["matrix"], totalPerPos)
            mi = miScore(st["pairCounts"])
            var = len(set(hx)) / 16.0

            mets.append({
                "name": names[idx],
                "ent": ent,

                "chiP": chiP,
                "runsP": runsP,

                "chiUse": chiUse,
                "runsUse": runsUse,

                "ham": ham,
                "bal": bal,
                "pos": pos,
                "mi": mi,
                "var": var,
                "pmScore": pmScore,
                "chiRaw": chiRaw
            })

            st["prevHex"] = hx
            st["count"] += 1

        for k, m in enumerate(mets):
            addPackMetricSums(
                stats[k]["packMetricSumsR"],
                [m["ent"], m["chiP"], m["runsP"], m["ham"], m["bal"], m["pos"], m["mi"], m["var"], m["pmScore"]]
            )

        rawVals = [0.0] * len(names)
        normVals = [0.0] * len(names)

        for k, m in enumerate(mets):
            rawVals[k] = (
                0.14 * m["ent"] +
                0.10 * m["chiUse"] +
                0.13 * m["runsUse"] +
                0.13 * m["ham"] +
                0.09 * m["bal"] +
                0.09 * m["pos"] +
                0.10 * m["mi"] +
                0.07 * m["var"] +
                0.15 * m["pmScore"]
            )
            packActSum[k] += rawVals[k]

        if needNorm:
            entA = [m["ent"] for m in mets]
            chiA = [m["chiUse"] for m in mets]
            runA = [m["runsUse"] for m in mets]
            hamA = [m["ham"] for m in mets]
            balA = [m["bal"] for m in mets]
            posA = [m["pos"] for m in mets]
            miA = [m["mi"] for m in mets]
            varA = [m["var"] for m in mets]
            pmA = [m["pmScore"] for m in mets]

            entN = maxNorm(entA)
            chiN = maxNorm(chiA)
            runN = maxNorm(runA)
            hamN = maxNorm(hamA)
            balN = maxNorm(balA)
            posN = maxNorm(posA)
            miN = maxNorm(miA)
            varN = maxNorm(varA)
            pmN = maxNorm(pmA)

            for k in range(len(names)):
                addPackMetricSums(
                    stats[k]["packMetricSumsN"],
                    [entN[k], chiN[k], runN[k], hamN[k], balN[k], posN[k], miN[k], varN[k], pmN[k]]
                )

            for k in range(len(names)):
                normVals[k] = (
                    0.14 * entN[k] +
                    0.10 * chiN[k] +
                    0.13 * runN[k] +
                    0.13 * hamN[k] +
                    0.09 * balN[k] +
                    0.09 * posN[k] +
                    0.10 * miN[k] +
                    0.07 * varN[k] +
                    0.15 * pmN[k]
                )
                packActSumNorm[k] += normVals[k]

        rawRat = [0.0] * len(names)
        normRat = [0.0] * len(names)

        if rawScores:
            rawRat = roundRatios(rawVals)
            masterRaw += 1.0
            packMasterRaw += 1.0
            for k in range(len(names)):
                stats[k]["packRaw"] += rawRat[k]
                if cumulative:
                    stats[k]["cumRaw"] += rawRat[k]

        if normalizedScores:
            normRat = roundRatios(normVals)
            masterNorm += 1.0
            packMasterNorm += 1.0
            for k in range(len(names)):
                stats[k]["packNorm"] += normRat[k]
                if cumulative:
                    stats[k]["cumNorm"] += normRat[k]

        if lightLog:
            row = [i, packIndex, inputLen]
            if rawScores:
                for k in range(len(names)):
                    row += [f"{rawVals[k]:.10f}", f"{rawRat[k]:.10f}"]
            if normalizedScores:
                for k in range(len(names)):
                    row += [f"{normVals[k]:.10f}", f"{normRat[k]:.10f}"]
            tsvRow(fp, row)
        else:
            for k in range(len(names)):
                m = mets[k]
                tsvRow(fp, [
                    i, packIndex, inputLen, preview, m["name"],
                    f"{m['ent']:.10f}",
                    f"{m['chiP']:.10f}",
                    f"{m['runsP']:.10f}",
                    f"{m['ham']:.10f}",
                    f"{m['bal']:.10f}",
                    f"{m['pos']:.10f}",
                    f"{m['mi']:.10f}",
                    f"{m['var']:.10f}",
                    f"{m['pmScore']:.10f}",
                    f"{m['chiRaw']:.10f}",
                    f"{rawVals[k]:.10f}",
                    f"{rawRat[k]:.10f}" if rawScores else "",
                    f"{normVals[k]:.10f}" if needNorm else "",
                    f"{normRat[k]:.10f}" if normalizedScores else "",
                ])

        if i % packSize == 0:
            packLen = i - packStartIter + 1
            packStartIter = i + 1
            packCount += 1

            mr = f"{masterRaw:.3f}" if rawScores else "-"
            mn = f"{masterNorm:.3f}" if normalizedScores else "-"

            cols = [str(i), str(packIndex), mr, mn]

            for k in range(len(names)):
                vR = 0.0
                vN = 0.0

                if rawScores:
                    if cumulative:
                        vR = (stats[k]["cumRaw"] / masterRaw) if masterRaw else 0.0
                    else:
                        vR = (stats[k]["packRaw"] / packMasterRaw) if packMasterRaw else 0.0
                        totalPackRaw[k] += vR
                    cols.append(f"{vR:.6f}")

                if normalizedScores:
                    if cumulative:
                        vN = (stats[k]["cumNorm"] / masterNorm) if masterNorm else 0.0
                    else:
                        vN = (stats[k]["packNorm"] / packMasterNorm) if packMasterNorm else 0.0
                        totalPackNorm[k] += vN
                    cols.append(f"{vN:.6f}")

                act = (packActSum[k] / packLen) if packLen else 0.0
                actCumSum[k] += act
                actCum = actCumSum[k] / packCount

                actN = 0.0
                actCumN = 0.0
                if needNorm:
                    actN = (packActSumNorm[k] / packLen) if packLen else 0.0
                    actCumSumNorm[k] += actN
                    actCumN = actCumSumNorm[k] / packCount

                if printAct:
                    cols.append(f"{act*100:.1f}")
                if printActNorm:
                    cols.append(f"{actN*100:.1f}")
                if printActCum:
                    cols.append(f"{actCum*100:.1f}")
                if printActCumNorm:
                    cols.append(f"{actCumN*100:.1f}")

                # ---- NEW ABS: weighted score from the 9 metric averages (always 0..1) ----
                if needNorm and normalizedScores:
                    avg = divPackMetricSums(stats[k]["packMetricSumsN"], packLen)
                    avgCell = [avg[0], avg[1], avg[2], avg[3], avg[4], avg[5], avg[6], avg[7], avg[8]]
                else:
                    avg = divPackMetricSums(stats[k]["packMetricSumsR"], packLen)
                    avgCell = [avg[0], avg[1], avg[2], avg[3], avg[4], avg[5], avg[6], avg[7], avg[8]]

                if printAbs:
                    abs01 = weightedScore01(avgCell, absMetricCfg)
                    cols.append(f"{abs01*100:.1f}")

                cols.append(metricsCell9(avgCell))

            printRow(cols, widths)

            if not cumulative:
                for st in stats:
                    resetAlgo(st)

            packActSum = [0.0] * len(names)
            packActSumNorm = [0.0] * len(names)

            if rawScores:
                packMasterRaw = 0.0
            if normalizedScores:
                packMasterNorm = 0.0

            for st in stats:
                st["packRaw"] = 0.0
                st["packNorm"] = 0.0
                st["packMetricSumsN"] = initPackMetricSums()
                st["packMetricSumsR"] = initPackMetricSums()

    fp.close()

    if not cumulative:
        if packCount <= 0:
            return
        print("\nFINAL TOTALS (pack-averaged)")
        for k in range(len(names)):
            if rawScores:
                r = totalPackRaw[k] / packCount
            else:
                r = None
            if normalizedScores:
                n = totalPackNorm[k] / packCount
            else:
                n = None

            if rawScores and normalizedScores:
                print(names[k], f"RAW={r:.6f}", f"NORM={n:.6f}")
            elif rawScores:
                print(names[k], f"RAW={r:.6f}")
            else:
                print(names[k], f"NORM={n:.6f}")
    else:
        print("\nFINAL TOTALS (cumulative)")
        for k in range(len(names)):
            r = (stats[k]["cumRaw"] / masterRaw) if rawScores and masterRaw else None
            n = (stats[k]["cumNorm"] / masterNorm) if normalizedScores and masterNorm else None
            if rawScores and normalizedScores:
                print(names[k], f"RAW={r:.6f}", f"NORM={n:.6f}")
            elif rawScores:
                print(names[k], f"RAW={r:.6f}")
            else:
                print(names[k], f"NORM={n:.6f}")

# =============================================================================
# USER TOGGLES
# =============================================================================
rawScores = True
normalizedScores = True # divides all scores in their respective categories by the highest score in that round
lightLog = True
showAllScores = True
printScoreLegendFlag = True
scoreDecimals = 0
cumulative = True # better if True for when iters is smaller, and pack size is 1 so that it can evaluate individual outputs

printAct = False
printActCum = False
printActNorm = False
printActCumNorm = False

printAbs = True

iters = 1000
packSize = 1
mode = 1
seed = 1
tsvPath = "rounds.tsv"
previewLen = 30

absMetricCfg = {
    "entropy":      [1, 6],
    "chi":          [1, 6],  # chi randomness
    "runs":         [1, 6],
    "hamming":      [1, 6],
    "balance":      [1, 6],
    "positional":   [1, 6],
    "mi":           [1, 6],  # transition MI
    "variance":     [1, 6],
    "distribution": [1, 6],
}

# =============================================================================
# ENTRY
# =============================================================================
if __name__ == "__main__":
    runCompare()