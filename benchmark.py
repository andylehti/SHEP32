#24A
import math, os, sys, time, string, hashlib, base64
from random import seed, randint, choice
from collections import Counter

sys.set_int_max_str_digits(0)

# =========================
# SHEP32 CORE (key-only path uses hashKey)
# =========================

_GCHAR_BASE = ''.join([x for x in string.printable[:90] if x not in '/\\`"\',_!#$%&()* +-=']) + '&()*$%/\\`"\',_!#'
def gChar(c): return _GCHAR_BASE[:c]

_TDEC_CACHE = {}

def encryptData(n, k=0):
    n = toBytes(n)
    hKey, e = hashKey(n)
    key, b = tDecimal(hKey, 16), e
    keys, n = [key] + [key := int(processKey(key)) for _ in range(9)], n + (key // b)
    n = pData(n, keys, b)
    return fDecimal(n, 62), hKey

def decryptData(n, k):
    e = getE(k)
    key, b, n = tDecimal(k, 16), e, tDecimal(n, 62)
    keys = [key] + [key := int(processKey(key)) for _ in range(9)]
    n = dData(n, keys, b)
    n = n - (key // b)
    return fromBytes(n)

def pData(n, keys, b):
    for key in keys:
        n = keySplit(n, key, 1)
        n = tDecimal(str(manipulateData(str(n), key)), 10)
        n = baseSplit(int(n), key, b, 1)
        n = kSplit(n, str(key))
        if int(str(key)[0]) % 2 == 1:
            n = int(interject(str(n)))
    return n

def dData(n, keys, b):
    for key in reversed(keys):
        if int(str(key)[0]) % 2 == 1:
            n = int(inverJect(str(n)))
        n = kSplit(n, str(key))
        n = fDecimal(baseSplit(int(n), key, b, 0), 10)
        n = inverseData(n, key)
        n = keySplit(int(n), key, 0)
    return n

def checkData(n, i):
    while n < 10**79: n *= 3; n, i = n + i, i + i
    s = str(n)
    n = sum(int(s[j:j+80]) for j in range(0, len(s), 80))
    return kSplit((int(qRotate(str(bSplit(n))) + processKey(n))), n)

def toBytes(t):
    b = b"\x01" + t.encode("utf-16-le", errors="surrogatepass")
    return int.from_bytes(b, 'big')

def fromBytes(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if not b or b[0] != 1: raise ValueError("byte sentinel missing")
    return b[1:].decode("utf-16-le", errors="surrogatepass")

def anyBase(n, b):
    if n == 0: return '0'
    d = []
    while n: d.append(str(n % b)); n //= b
    return ' '.join(d[::-1])

def hashKey(n): return getB(fetchKey(n))
def fetchKey(n): return manipulateKey(tDecimal(manipulateData(getKey(checkData(n+90, (n % 7) + 1), 79), n), 10))
def manipulateKey(n): return fDecimal(tDecimal(hex(n)[2:], 16) + int(fDecimal(n, 16), 16), 16)[-63:-1]
def getKey(n, x=78): return next(str(n) for _ in iter(int, 1) if len(str(n := (n // 8) + int(Ep(str(n // 5), len(str(n)))))) <= x)

def fromAnyBase(n, b):
    res = 0
    for p in n.split(): res = res * b + int(p)
    return res

def generateSeries(s, n): seed(s); return ''.join(str(randint(0, 8)) for _ in range(n))
def manipulateData(s, c): k = generateSeries(c, len(str(s))); return ''.join(str((int(str(s)[i]) + int(k[i])) % 10) for i in range(len(str(s))))
def inverseData(s, c): k = generateSeries(c, len(str(s))); return ''.join(str((int(str(s)[i]) - int(k[i])) % 10) for i in range(len(str(s))))
def qRotate(s): return s[5:] + s[2:5][::-1] + s[:2]
def pRotate(s): return s[-2:] + s[-5:-2][::-1] + s[:-5]
def interject(s): s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, ''); h = len(s) // 2; return ''.join(x + y for x, y in zip(s[:h], s[h:])) + p
def inverJect(s): s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, ''); return ''.join(s[i] for i in range(0, len(s), 2)) + ''.join(s[i] for i in range(1, len(s), 2)) + p
def keySplit(n, k, y=1): m = str(k) if y == 1 else str(k)[::-1]; return [n := bSplit(n, int(d) + 2) for d in m][-1]
def bSplit(s, f=4): s = bin(s)[3:]; return int('1' + ''.join(s[i:i+f][::-1] for i in range(0, len(s) - len(s) % f, f)) + s[len(s) - len(s) % f:], 2)

def kSplit(s, k):
    s_bin = bin(s)[3:]
    k_str = str(k).replace('0', '')
    if not k_str: return int('1' + s_bin[::-1], 2)

    k_digits = [int(d) + 1 for d in k_str]
    k_len, s_len = len(k_digits), len(s_bin)
    chunks, idx, k_idx = [], 0, 0

    while idx < s_len:
        step = k_digits[k_idx % k_len]
        chunks.append(s_bin[idx : idx + step][::-1])
        idx += step
        k_idx += 1

    return int('1' + ''.join(chunks), 2)

def Ap(n, m, p): return str(int(n) * int(m))[:p]
def Bp(n, p): return ''.join(str((int(n[i % len(n)]) + int(n[0])) % 10) for i in range(p))
def Cp(n, m, p): return str(int(n) * int(n[:3 % len(n)]))[:p]
def Dp(n, m, p): return (''.join(str(abs(int(n[i % len(n)]) * int(m[i % len(m)]))) for i in range(p)))[:p]
def Ep(n, p): return str(sum(map(int, ' '.join(str(math.pi * (1/(int(n[i % len(n)]) + 1)/(int(n[(i+1) % len(n)]) + 1)) - int(math.pi * (1/(int(n[i % len(n)]) + 1)/(int(n[(i+1) % len(n)]) + 1))))[2:] for i in range(p)).split())))[-p:]

def processKey(n, m=0):
    n, m = str(n), str(m) if m else str(n)
    p, r = len(n), int(n[0])
    t = int(n[int(m[int(n[0])]) % p]) if len(m) > int(n[0]) else int(n[-1])
    a, b = (r + t) % 6, (r - t) % 6
    n = Ap(n, m, p) if a == 0 else Bp(n, p) if a == 1 else Cp(n, m, p) if a == 2 else Dp(n, m, p) if a == 3 else Ep(n, p) if a == 4 else Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p)
    n = Cp(n, m, p) if b == 0 else Dp(n, m, p) if b == 1 else Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p) if b == 2 else Bp(n, p) if b == 3 else Ap(n, m, p) if b == 4 else Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p)
    a, b = next((x for x in n if x.isdigit() and x != '0'), '2'), next((x for x in n[1:] if x.isdigit() and x != '0'), '3')
    n = str(bSplit(bSplit(int(n) + int(pRotate(n)))))
    n = tDecimal(qRotate(str(n)), 10)
    return str(int(int(n) + int(a + b + '0' * (p-2))) + int(m))[-p:]

def fDecimal(d, b):
    c, n, r = gChar(b), 1, d
    bn = b
    while r >= bn: r -= bn; n += 1; bn *= b
    if n == 0: return ""
    out = []
    for _ in range(n):
        out.append(c[r % b])
        r //= b
    return ''.join(reversed(out)).zfill(n)

def tDecimal(c, b):
    if b not in _TDEC_CACHE: _TDEC_CACHE[b] = {ch: i for i, ch in enumerate(gChar(b))}
    char_map, s = _TDEC_CACHE[b], str(c)
    l = len(s)
    v = sum(char_map[ch] * (b ** i) for i, ch in enumerate(reversed(s)))
    geom_sum = (b ** l - b) // (b - 1) if b > 1 and l > 1 else (l - 1 if b == 1 and l > 1 else 0)
    return v + geom_sum

def baseSplit(n, k, b=8, y=1):
    m = 2 ** 16
    nDigits = anyBase(n, b).split()
    z = [x for x in anyBase(k, m).split() if 2 <= len(x) <= 10]
    if not z: z = [str((k % (m - 2)) + 2)]

    cap = (len(nDigits) + 2) * 40
    loops = 0
    target_len = len(nDigits) + 1 if y == 1 else len(nDigits)

    while len(z) < target_len:
        z.extend(x for x in anyBase(k, int(z[-1]) + m).split() if 2 <= len(x) <= 10)
        loops += 1
        if loops > cap: break

    if len(z) < target_len: z.extend([z[-1]] * (target_len - len(z)))

    if y == 1:
        guard = (1 - (int(z[0]) % b)) % b
        nDigits = [str(guard)] + nDigits
        return fromAnyBase(' '.join(str((int(x) + int(zv)) % b) for x, zv in zip(nDigits, z)), b)

    outDigits = [str((int(x) - int(zv)) % b) for x, zv in zip(nDigits, z)]
    return 0 if len(outDigits) <= 1 else fromAnyBase(' '.join(outDigits[1:]), b)

def fold64(h):
    h = ''.join(c for c in h.lower() if c in '0123456789abcdef')
    if not h: return '0' * 64
    if len(h) < 64: return h * ((64 // len(h)) + 1)
    out = [0] * 64
    for i, ch in enumerate(h): out[i % 64] ^= int(ch, 16)
    return ''.join('0123456789abcdef'[x] for x in out)

def getE(hex64):
    x = hex64.lower().zfill(64)[-64:]
    s4 = (str(int(x[:4], 16) + int(x[-4:], 16)).lstrip('0') or '0')[:4]
    n = int(s4)
    if n < 4096: return n
    if n % 2 == 0: return int(s4[:-1]) + (100 if len(s4) > 1 and s4[-2] == "0" else 0)
    return int(s4[1:]) + (100 if len(s4) > 1 and s4[1] == "0" else 0)

def getB(hexStr):
    h = fold64(hexStr)
    f = int(h[:4], 16)
    l = int(h[-4:], 16)
    seed_val = ((f >> 8) ^ (l & 0xFF) ^ (f & 0xFF) ^ (l >> 8)) & 0xFF

    mh = ''.join(f'{((int(h[i:i+2], 16) - seed_val) & 0xFF):02x}' for i in range(0, 64, 2))
    mh = hex(int(mh, 16) + int(h, 16))[2:]

    baseParam = int(mh[:4].zfill(4), 16)
    nVal = int(mh, 16)
    kVal = int(mh[-4:].zfill(4), 16)

    splitVal = baseSplit(nVal, kVal, b=(baseParam & 4096) + 64, y=1)
    splitHex = hex(splitVal)[2:]

    sFull = hex(int(h, 16) + int(splitHex, 16))[2:]
    s = fold64(sFull)
    
    e = getE(s)
    return s, e

n = 'Andrew Lehti'
n, k = encryptData(n)
print(n, k)
n = decryptData(n, k)
print(n)

def shepKeyFromString(s): return getB(fetchKey(toBytes(s)))[0].lower()

# =========================
# UTIL
# =========================

def safeB64Utf8(s): return base64.b64encode(s.encode("utf-8", errors="surrogatepass")).decode("ascii")
def safePreview(s, maxLen=90):
    r = repr(s)
    return r if len(r) <= maxLen else (r[:maxLen - 1] + "…")
def readLines(path):
    try:
        with open(path, "r", encoding="utf-8") as f: return [line.strip() for line in f if line.strip()]
    except Exception: return []
def fmt(v, w):
    s = str(v)
    return (s[:w - 1] + "…") if len(s) > w else (s + " " * (w - len(s)))

# =========================
# MATRIX RATIO SCORING
# =========================

_HEXCH = "0123456789abcdef"
_HEXMAP = {c: i for i, c in enumerate(_HEXCH)}
_L1MAX = 2.0 * (1.0 - (1.0 / 16.0))  # 1.875

def initMatrix():
    return {"N": 0, "pos": [[0] * 16 for _ in range(64)], "gc": [0] * 16}

def pushHex(mx, hx):
    if not isinstance(hx, str) or len(hx) != 64: raise ValueError("String must be exactly 64 characters.")
    s = hx.lower(); mx["N"] += 1
    pos, gc = mx["pos"], mx["gc"]
    for i, ch in enumerate(s):
        v = _HEXMAP.get(ch, 0)
        pos[i][v] += 1; gc[v] += 1

def posUniform(mx):
    N = mx["N"]
    if N <= 0: return 0.0
    u = 1.0 / 16.0; tot = 0.0
    for p in range(64):
        row = mx["pos"][p]; l1 = 0.0
        for c in row: l1 += abs((c / N) - u)
        tot += (1.0 - (l1 / _L1MAX))
    return max(0.0, min(1.0, tot / 64.0))

def globalUniform(mx):
    N = mx["N"]
    if N <= 0: return 0.0
    total = 64.0 * N; u = 1.0 / 16.0; l1 = 0.0
    for c in mx["gc"]: l1 += abs((c / total) - u)
    return max(0.0, min(1.0, 1.0 - (l1 / _L1MAX)))

# =========================
# BIT-LEVEL METRICS
# =========================

def hexToBits(h):
    bits = []
    for ch in (h or "").strip().lower():
        if "0" <= ch <= "9": v = ord(ch) - 48
        elif "a" <= ch <= "f": v = ord(ch) - 87
        else: continue
        bits.extend([(v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1])
    return bits

def shannonEntropyBit(p1):
    if p1 <= 0.0 or p1 >= 1.0: return 0.0
    p0 = 1.0 - p1
    return -(p0 * math.log(p0, 2) + p1 * math.log(p1, 2))

def runsTestP(bits):
    n = len(bits)
    if n < 2: return 0.0
    ones = sum(bits); pi = ones / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n): return 0.0
    v = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]: v += 1
    num = abs(v - (2.0 * n * pi * (1.0 - pi)))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    return 0.0 if den == 0 else math.erfc(num / den)

def hamming(aBits, bBits):
    m = min(len(aBits), len(bBits))
    return sum(1 for i in range(m) if aBits[i] != bBits[i])

def keyStats(hexList):
    if not hexList: return 0, 0.0, 0.0, 0.0, 0.0
    perBits = [hexToBits(x) for x in hexList]; perBits = [b for b in perBits if b]
    if not perBits: return 0, 0.0, 0.0, 0.0, 0.0
    bitLen = len(perBits[0]); allBits = []
    for b in perBits: allBits.extend(b)
    n = len(allBits); ones = sum(allBits)
    onesPct = (ones * 100.0 / n) if n else 0.0
    ent = shannonEntropyBit((ones / n) if n else 0.0)
    runsP = runsTestP(allBits)
    avgHam = 0.0
    if len(perBits) >= 2:
        hs = 0; c = 0
        for i in range(1, len(perBits)): hs += hamming(perBits[i - 1], perBits[i]); c += 1
        avgHam = (hs / c) if c else 0.0
    return bitLen, onesPct, ent, runsP, avgHam

def bitAbsScore(bitLen, onesPct, ent, runsP, avgHam):
    if bitLen <= 0: return 0.0
    biasN = ((onesPct - 50.0) / 50.0) ** 2
    entN = (1.0 - max(0.0, min(1.0, ent))) ** 2
    hamFrac = (avgHam / bitLen) if bitLen else 0.0
    hamN = ((hamFrac - 0.5) / 0.5) ** 2
    rp = max(0.0, min(1.0, runsP))
    runN = ((rp - 0.5) / 0.5) ** 2
    wBias, wEnt, wHam, wRun = 0.18, 0.18, 0.44, 0.20
    bad = (wBias * biasN) + (wEnt * entN) + (wHam * hamN) + (wRun * runN)
    return 100.0 * max(0.0, min(1.0, 1.0 - bad))

def matrixAbsScore(posU, globU): return 100.0 * (0.85 * posU + 0.15 * globU)

def clamp(x, lo, hi): return lo if x < lo else hi if x > hi else x

def fairPairScores(absA, absB):
    bandA = 90.0 + 9.0 * (absA / 100.0)
    bandB = 90.0 + 9.0 * (absB / 100.0)
    base = 0.5 * (bandA + bandB)
    d = absA - absB
    delta = 2.25 * math.tanh(d / 10.0)  # small differences => tiny delta, big differences => capped
    a = clamp(base + delta, 90.0, 99.5)
    b = clamp(base - delta, 90.0, 99.5)
    return a, b

# =========================
# INPUT GENERATION
# =========================

def canUtf16(ch):
    try: ch.encode("utf-16-le"); return True
    except Exception: return False

def makePool(cat, uniN=0):
    if cat == "a-z": return [chr(i) for i in range(ord("a"), ord("z") + 1)]
    if cat == "A-Z": return [chr(i) for i in range(ord("A"), ord("Z") + 1)]
    if cat == "A-Za-z": return [chr(i) for i in range(ord("a"), ord("z") + 1)] + [chr(i) for i in range(ord("A"), ord("Z") + 1)]
    if cat == "0-9": return [chr(i) for i in range(ord("0"), ord("9") + 1)]
    if cat == "a-zA-Z0-9": return makePool("A-Za-z") + makePool("0-9")
    if cat == "a-zA-Z0-9 ": return makePool("a-zA-Z0-9") + [" "]
    if cat.startswith("unicode"):
        pool = []
        for cp in range(uniN):
            if 0xD800 <= cp <= 0xDFFF: continue
            ch = chr(cp)
            if canUtf16(ch): pool.append(ch)
        return pool if pool else [" "]
    return ["x"]

def randStr(pool, lo=5, hi=100):
    n = randint(lo, hi)
    return "".join(choice(pool) for _ in range(n))

# =========================
# REPORT PRINTING
# =========================

def printHeader():
    cols = [
        ("iter", 7), ("category", 18), ("len", 4), ("shepOk", 6), ("shaOk", 5),
        ("shepOnes", 8), ("shaOnes", 7), ("shepEnt", 7), ("shaEnt", 6),
        ("shepRuns", 8), ("shaRuns", 7), ("shepHam", 8), ("shaHam", 7),
        ("shepPosU", 9), ("shaPosU", 8), ("shepGlobU", 10), ("shaGlobU", 9),
        ("shepAbs", 8), ("shaAbs", 7), ("shepFinal", 9), ("shaFinal", 8), ("better", 7),
    ]
    line = " | ".join(fmt(n, w) for n, w in cols); bar = "-+-".join("-" * w for _, w in cols)
    print(line); print(bar)

# =========================
# RUNNER
# =========================

def runTests(iters=5000, reportEvery=100, seedVal=1, uniSteps=None, mode=0, chunkLen=32, startCp=0, endCp=0x10FFFF,
             shepKeyFile="shepKeys.tmp", shaFile="sha256.tmp"):
    seed(seedVal)
    if uniSteps is None: uniSteps = [100, 500, 1000, 2000, 5000, 10000]
    cats = [("a-z", 0), ("A-Z", 0), ("A-Za-z", 0), ("0-9", 0), ("a-zA-Z0-9", 0), ("a-zA-Z0-9 ", 0)] + [(f"unicode{n}", n) for n in uniSteps]
    pools = {c: makePool(c, n) for c, n in cats}
    with open(shepKeyFile, "w", encoding="utf-8", newline="\n") as f: f.write("")
    with open(shaFile, "w", encoding="utf-8", newline="\n") as f: f.write("")

    shepOk = 0; shaOk = 0; cp = startCp
    shepWin = []; shaWin = []
    shepMxAll = initMatrix(); shaMxAll = initMatrix()

    t0 = time.perf_counter(); printHeader()

    for i in range(1, iters + 1):
        if mode == 0:
            cat, _ = cats[randint(0, len(cats) - 1)]
            s = randStr(pools[cat], 5, 100)
        elif mode == 1:
            if cp > endCp: break
            a = cp; b = min(endCp, cp + chunkLen - 1)
            s = "".join(chr(x) for x in range(a, b + 1) if not (0xD800 <= x <= 0xDFFF))
            cat = f"unicodeSeqChunk(cp={a}..{b},len={chunkLen})"; cp = b + 1
        elif mode == 3:
            if cp > endCp: break
            while 0xD800 <= cp <= 0xDFFF and cp <= endCp: cp += 1
            if cp > endCp: break
            s = chr(cp); cat = f"unicodeInc1(cp={cp})"; cp += 1
        else:
            raise ValueError("mode must be 0, 1, or 3")

        shaHex = hashlib.sha256(s.encode("utf-8", errors="surrogatepass")).hexdigest().lower()
        with open(shaFile, "a", encoding="utf-8", newline="\n") as f: f.write(shaHex + "\n")
        pushHex(shaMxAll, shaHex); shaOk += 1
        shaWin.append(shaHex); 
        if len(shaWin) > reportEvery: shaWin.pop(0)

        k = shepKeyFromString(s)
        with open(shepKeyFile, "a", encoding="utf-8", newline="\n") as f: f.write(k + "\n")
        pushHex(shepMxAll, k); shepOk += 1
        shepWin.append(k)
        if len(shepWin) > reportEvery: shepWin.pop(0)

        if i % reportEvery == 0:
            sBL, sOn, sEn, sRn, sHm = keyStats(readLines(shepKeyFile))
            hBL, hOn, hEn, hRn, hHm = keyStats(readLines(shaFile))

            sBit = bitAbsScore(sBL, sOn, sEn, sRn, sHm)
            hBit = bitAbsScore(hBL, hOn, hEn, hRn, hHm)

            sPosU, sGlobU = posUniform(shepMxAll), globalUniform(shepMxAll)
            hPosU, hGlobU = posUniform(shaMxAll), globalUniform(shaMxAll)

            sMat = matrixAbsScore(sPosU, sGlobU)
            hMat = matrixAbsScore(hPosU, hGlobU)

            sAbs = (0.55 * sBit) + (0.45 * sMat)
            hAbs = (0.55 * hBit) + (0.45 * hMat)

            shepFinal, shaFinal = fairPairScores(sAbs, hAbs)
            better = "SHEP32" if shepFinal > shaFinal else "SHA256" if shaFinal > shepFinal else "TIE"

            rowOut = [
                i, cat, len(s), shepOk, shaOk,
                f"{sOn:0.2f}", f"{hOn:0.2f}", f"{sEn:0.3f}", f"{hEn:0.3f}",
                f"{sRn:0.4f}", f"{hRn:0.4f}", f"{sHm:0.2f}", f"{hHm:0.2f}",
                f"{(100.0 * sPosU):0.2f}", f"{(100.0 * hPosU):0.2f}",
                f"{(100.0 * sGlobU):0.2f}", f"{(100.0 * hGlobU):0.2f}",
                f"{sAbs:0.2f}", f"{hAbs:0.2f}",
                f"{shepFinal:0.2f}", f"{shaFinal:0.2f}", better,
            ]
            widths = [7, 18, 4, 6, 5, 8, 7, 7, 6, 8, 7, 8, 7, 9, 8, 10, 9, 8, 7, 9, 8, 7]
            print(" | ".join(fmt(v, w) for v, w in zip(rowOut, widths)))

    dt = time.perf_counter() - t0
    print("\nSummary")
    print(f"iterationsRan={shepOk} elapsedSec={dt:.3f}")
    print(f"shepKeyFile={os.path.abspath(shepKeyFile)}")
    print(f"shaFile={os.path.abspath(shaFile)}")

# =========================
# NOTE:
# iters=8000
# Total iterations to run (upper bound). In mode=1 or mode=3 the loop may end early if cp > endCp.
#
# reportEvery=10
# Print one summary row every N iterations, and compute window-stats over the last N hashes/keys.
#
# seedVal=1
# RNG seed for reproducible runs (affects category choice in mode=0 and random string generation).
#
# uniSteps=[100, 500, 1000, 2000, 5000, 10000]
# Unicode pool sizes for the "unicodeN" categories in mode=0. Each creates a pool from codepoints [0..N-1]
# excluding surrogate range; larger N expands the random input search space.
#
# mode=3
# Input mode selector:
# 0 = random strings length 5..100 from random category pools
# 1 = sequential unicode chunks: chr(cp..cp+chunkLen-1) per iteration
# 3 = increment-by-1 unicode: ONE character per iteration, starting at startCp
#
# chunkLen=32
# Used only in mode=1 (sequential chunk mode). Size of each unicode block per iteration.
#
# startCp=1680
# Starting Unicode codepoint for mode=1 or mode=3 (skips surrogate range automatically in mode=3).
#
# endCp=0x10FFFF
# Ending Unicode codepoint (inclusive) for mode=1 or mode=3. Loop stops once cp exceeds this value.
# =========================

if __name__ == "__main__":
    runTests(iters=20000, reportEvery=100, seedVal=1, uniSteps=[100, 500, 1000, 2000, 5000, 10000],
             mode=0, chunkLen=32, startCp=0, endCp=0x10FFFF, shepKeyFile="shepKeys.tmp", shaFile="sha256.tmp")
