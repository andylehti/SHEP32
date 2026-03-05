# Main imports
import math, os, sys, time, zlib

# Python CLI
import argparse
from pathlib import Path

sys.set_int_max_str_digits(0)

# =========================
# Hardcoded character base (portable)
# Build Version: 38A
# NOTES: Builds prior to Build 38A no longer use the same encryption or decryption
# =========================
gCharBase = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:;<>?@[]^&()*$%/\\`\"',_!#"
def gChar(c): return gCharBase[:c]

tDecCache = {}
ten79 = 10 ** 79

# =========================
# Small portable helpers
# =========================
def splitWs(s): return s.split()

def isHex64(k):
    if not isinstance(k, str) or len(k) != 64: return False
    for ch in k:
        o = ord(ch)
        if not (48 <= o <= 57 or 65 <= o <= 70 or 97 <= o <= 102):  # 0-9 A-F a-f
            return False
    return True

def hexLower(n): return format(int(n), "x")

def binTail(n):
    b = format(int(n), "b")
    return "" if len(b) <= 1 else b[1:]  # drop leading '1', matches bin(n)[3:] for n>0

def _printProg(label, i, total):
    if total <= 0: return
    pct = int((i * 100) / total)
    sys.stdout.write(f"\r{label} {i}/{total} ({pct}%)")
    sys.stdout.flush()
    if i >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()

def _obfuscateProg(text, keyHex, steps, baseLabel, done, total):
    if steps != 64:
        _printProg(baseLabel, done + 1, total)
        return obfuscate(text, keyHex, steps)

    _printProg(baseLabel, done + 1, total)
    seeds = deriveSeeds(keyHex, steps)
    t = text
    mid = len(seeds) // 2
    for i, s in enumerate(seeds):
        t = permuteBySeed(t, s)
        if i + 1 == mid:
            _printProg(baseLabel, done + 2, total)
    _printProg(baseLabel, done + 3, total)
    return t

def _deobfuscateProg(obfText, keyHex, steps, baseLabel, done, total):
    if steps != 64:
        _printProg(baseLabel, done + 1, total)
        return deobfuscate(obfText, keyHex, steps)

    _printProg(baseLabel, done + 1, total)
    seeds = deriveSeeds(keyHex, steps)
    t = obfText
    mid = len(seeds) // 2
    for i, s in enumerate(reversed(seeds)):
        t = unpermuteBySeed(t, s)
        if i + 1 == mid:
            _printProg(baseLabel, done + 2, total)
    _printProg(baseLabel, done + 3, total)
    return t

def _plainSizeBytes(s):
    return 1 + len(s.encode("utf-16-le", errors="surrogatepass"))

def _sepChar(i):
    a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return a[i % len(a)]

# =========================
# Deterministic MT19937 (Python-compatible seeding + randrange core)
# =========================
class DeterministicRng32:
    def __init__(self, seedValue=1):
        self.n = 624
        self.m = 397
        self.matrixA = 0x9908b0df
        self.upperMask = 0x80000000
        self.lowerMask = 0x7fffffff
        self.mt = [0] * self.n
        self.mti = self.n + 1
        self.setSeed(seedValue)

    def setSeed(self, seedValue):
        if seedValue is None:
            seedValue = int.from_bytes(os.urandom(32), "big") ^ time.time_ns()
        x = int(seedValue)
        if x < 0: x = -x
        key = []
        while x:
            key.append(x & 0xFFFFFFFF)
            x >>= 32
        if not key:
            key = [0]
        self.initByArray(key)

    def initGenrand(self, s):
        self.mt[0] = int(s) & 0xFFFFFFFF
        for i in range(1, self.n):
            self.mt[i] = (1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & 0xFFFFFFFF
        self.mti = self.n

    def initByArray(self, initKey):
        self.initGenrand(19650218)
        i = 1
        j = 0
        keyLength = len(initKey)
        for _ in range(max(self.n, keyLength), 0, -1):
            self.mt[i] = (self.mt[i] ^ ((self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) * 1664525)) + initKey[j] + j
            self.mt[i] &= 0xFFFFFFFF
            i += 1
            j += 1
            if i >= self.n:
                self.mt[0] = self.mt[self.n - 1]
                i = 1
            if j >= keyLength:
                j = 0
        for _ in range(self.n - 1, 0, -1):
            self.mt[i] = (self.mt[i] ^ ((self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) * 1566083941)) - i
            self.mt[i] &= 0xFFFFFFFF
            i += 1
            if i >= self.n:
                self.mt[0] = self.mt[self.n - 1]
                i = 1
        self.mt[0] = 0x80000000
        self.mti = self.n

    def nextU32(self):
        if self.mti >= self.n:
            mag01 = [0, self.matrixA]
            for kk in range(self.n - self.m):
                y = (self.mt[kk] & self.upperMask) | (self.mt[kk + 1] & self.lowerMask)
                self.mt[kk] = self.mt[kk + self.m] ^ (y >> 1) ^ mag01[y & 1]
            for kk in range(self.n - self.m, self.n - 1):
                y = (self.mt[kk] & self.upperMask) | (self.mt[kk + 1] & self.lowerMask)
                self.mt[kk] = self.mt[kk + (self.m - self.n)] ^ (y >> 1) ^ mag01[y & 1]
            y = (self.mt[self.n - 1] & self.upperMask) | (self.mt[0] & self.lowerMask)
            self.mt[self.n - 1] = self.mt[self.m - 1] ^ (y >> 1) ^ mag01[y & 1]
            self.mti = 0

        y = self.mt[self.mti]
        self.mti += 1

        y ^= (y >> 11)
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= (y >> 18)

        return y & 0xFFFFFFFF

    def getRandBits(self, k):
        k = int(k)
        if k <= 0:
            return 0
        words = (k + 31) // 32
        x = 0
        for _ in range(words):
            x = (x << 32) | self.nextU32()
        extra = words * 32 - k
        if extra:
            x >>= extra
        return x

    def randBelow(self, n):
        n = int(n)
        if n <= 0:
            raise ValueError("n must be > 0")
        k = n.bit_length()
        while True:
            r = self.getRandBits(k)
            if r < n:
                return r

    def randint(self, a, b):
        a = int(a); b = int(b)
        if a > b:
            raise ValueError("a must be <= b")
        return a + self.randBelow(b - a + 1)

    def shuffle(self, arr):
        for i in range(len(arr) - 1, 0, -1):
            j = self.randBelow(i + 1)
            arr[i], arr[j] = arr[j], arr[i]
        return arr

# =========================
# SHEP32 CHUNKING
# =========================

# 3) ADD to: SHEP32 CHUNKING section (below deobfuscate is fine)

def _toBytesBin(b):
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise ValueError("_toBytesBin expects bytes")
    bb = b"\x01" + bytes(b)
    return int.from_bytes(bb, "big")

def _fromBytesBin(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if not b or b[0] != 1:
        raise ValueError("byte sentinel missing")
    return b[1:]

def _chunkBytes(b, chunkSize=2048):
    if chunkSize <= 0:
        raise ValueError("chunkSize must be > 0")
    b = bytes(b)
    if not b:
        return [b""]
    return [b[i:i + chunkSize] for i in range(0, len(b), chunkSize)]

def _buildHeader(chunkSize, origLen, compLen, lens):
    out = ["shz1"]
    nums = [str(int(chunkSize)), str(int(origLen)), str(int(compLen)), str(int(len(lens)))]
    nums.extend(str(int(x)) for x in lens)
    for i, v in enumerate(nums):
        out.append(v)
        if i != len(nums) - 1:
            out.append(_sepChar(i))
    out.append("a0a0")
    return "".join(out)

def _parseHeader(payload):
    if not payload.startswith("shz1"):
        raise ValueError("missing header prefix")
    t = payload.find("a0a0")
    if t == -1:
        raise ValueError("missing header terminator")
    header = payload[:t + 4]
    body = payload[t + 4:]

    core = header[4:-4]
    if not core:
        raise ValueError("empty header core")

    nums = []
    i = 0
    sepIdx = 0
    n = len(core)

    while i < n:
        j = i
        while j < n and 48 <= ord(core[j]) <= 57:
            j += 1
        if j == i:
            raise ValueError("expected digits in header")
        nums.append(int(core[i:j]))
        if j == n:
            break
        expected = _sepChar(sepIdx)
        if core[j] != expected:
            raise ValueError("header separator mismatch")
        sepIdx += 1
        i = j + 1

    if len(nums) < 4:
        raise ValueError("header too short")

    chunkSize = nums[0]
    origLen = nums[1]
    compLen = nums[2]
    total = nums[3]
    lens = nums[4:]

    if total != len(lens):
        raise ValueError("chunk count mismatch")

    return header, body, chunkSize, origLen, compLen, lens

def _encryptIntWithKey(nInt, hKey):
    e = getE(hKey)
    key0 = tDecimal(hKey, 16)
    b = e
    keys = [key0]
    key = key0
    for _ in range(9):
        key = int(processKey(key))
        keys.append(key)
    nInt = nInt + (key // b)
    nInt = pData(nInt, keys, b)
    return fDecimal(nInt, 62)

def _decryptIntWithKey(cText, hKey):
    e = getE(hKey)
    key0 = tDecimal(hKey, 16)
    b = e
    nInt = tDecimal(cText, 62)
    keys = [key0]
    key = key0
    for _ in range(9):
        key = int(processKey(key))
        keys.append(key)
    nInt = dData(nInt, keys, b)
    nInt = nInt - (key // b)
    return nInt

def _hexNibble(c):
    o = ord(c)
    if 48 <= o <= 57: return o - 48
    if 97 <= o <= 102: return o - 87
    if 65 <= o <= 70: return o - 55
    raise ValueError("non-hex")

def _hexToNibbles(h):
    if not isinstance(h, str) or len(h) != 64:
        raise ValueError("keyHex must be 64 hex chars")
    return [_hexNibble(c) for c in h]

def _lcg(x):
    return (48271 * (x % 2147483647)) % 2147483647

def _idx(n, s):
    r = list(range(n)); x = s or 1
    for i in range(n - 1, 0, -1):
        x = _lcg(x); j = x % (i + 1); r[i], r[j] = r[j], r[i]
    return r

def permuteBySeed(t, s):
    n = len(t)
    if n < 2: return t
    r = _idx(n, s)
    return "".join(t[i] for i in r)

def unpermuteBySeed(t, s):
    n = len(t)
    if n < 2: return t
    r = _idx(n, s); inv = [0] * n
    for p, i in enumerate(r): inv[i] = p
    return "".join(t[inv[i]] for i in range(n))

def deriveSeeds(keyHex, steps):
    nibbles = _hexToNibbles(keyHex)
    m = 2147483647
    acc = 1
    cum = 0
    out = [0] * steps
    for i in range(steps):
        v = nibbles[i % len(nibbles)]
        acc = (acc * 131 + v + 1) % m
        cum = (cum + acc + (i + 1) * 17) % m
        out[i] = cum or 1
    return out

def obfuscate(text, keyHex, steps=64):
    seeds = deriveSeeds(keyHex, steps)
    t = text
    for s in seeds:
        t = permuteBySeed(t, s)
    return t

def deobfuscate(obfText, keyHex, steps=64):
    seeds = deriveSeeds(keyHex, steps)
    t = obfText
    for s in reversed(seeds):
        t = unpermuteBySeed(t, s)
    return t

# =========================
# SHEP32 CORE
# =========================
def toBytes(t):
    b = b"\x01" + t.encode("utf-16-le", errors="surrogatepass")
    return int.from_bytes(b, "big")

def fromBytes(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if not b or b[0] != 1: raise ValueError("byte sentinel missing")
    return b[1:].decode("utf-16-le", errors="surrogatepass")

def fastAnyBaseList(val, b):
    if val == 0: return ["0"]
    powers = [(1, b)]
    while powers[-1][1] <= val: powers.append((powers[-1][0] * 2, powers[-1][1] ** 2))
    n = 0; curBn = 1
    for pN, pVal in reversed(powers):
        if curBn * pVal <= val: curBn *= pVal; n += pN
    n += 1
    def convert(v, targetLen):
        if targetLen <= 500:
            out = []
            for _ in range(targetLen): out.append(str(v % b)); v //= b
            return out[::-1]
        half = targetLen // 2; divisor = b ** half
        upperVal, lowerVal = divmod(v, divisor)
        return convert(upperVal, targetLen - half) + convert(lowerVal, half)
    res = convert(val, n)
    while len(res) > 1 and res[0] == "0": res.pop(0)
    return res

def anyBase(n, b): return " ".join(fastAnyBaseList(n, b))

def fromAnyBase(n, b):
    parts = splitWs(n) if isinstance(n, str) else n
    if not parts: return 0
    ints = [int(p) for p in parts]
    def evalRange(start, end):
        if end - start <= 200:
            res = 0
            for i in range(start, end): res = res * b + ints[i]
            return res
        mid = (start + end) // 2
        return evalRange(start, mid) * (b ** (end - mid)) + evalRange(mid, end)
    return evalRange(0, len(ints))

def fastBaseConvert(val, b, padTo, charset):
    if padTo <= 500:
        out = []
        for _ in range(padTo): out.append(charset[val % b]); val //= b
        return "".join(reversed(out))
    half = padTo // 2; divisor = b ** half
    upperVal, lowerVal = divmod(val, divisor)
    return fastBaseConvert(upperVal, b, padTo - half, charset) + fastBaseConvert(lowerVal, b, half, charset)

def fDecimal(d, b):
    c = gChar(b)
    if b == 1: return c[0] * (d + 1)
    target = d * (b - 1) + b
    powers = [(1, b)]
    while powers[-1][1] <= target: powers.append((powers[-1][0] * 2, powers[-1][1] ** 2))
    n = 0; curBn = 1
    for pN, pVal in reversed(powers):
        if curBn * pVal <= target: curBn *= pVal; n += pN
    geomSum = (b ** n - b) // (b - 1) if n > 0 else 0
    r = d - geomSum
    return "" if n == 0 else fastBaseConvert(r, b, n, c)

def tDecimal(c, b):
    s = str(c); l = len(s)
    if b == 10: return int(s) + ((10 ** l - 10) // 9 if l > 1 else 0)
    if b == 16: return int(s, 16) + ((16 ** l - 16) // 15 if l > 1 else 0)
    if b not in tDecCache: tDecCache[b] = {ch: i for i, ch in enumerate(gChar(b))}
    charMap = tDecCache[b]
    def evalRange(start, end):
        if end - start <= 200:
            res = 0
            for i in range(start, end): res = res * b + charMap[s[i]]
            return res
        mid = (start + end) // 2
        return evalRange(start, mid) * (b ** (end - mid)) + evalRange(mid, end)
    v = evalRange(0, l)
    geomSum = (b ** l - b) // (b - 1) if b > 1 and l > 1 else (l - 1 if b == 1 and l > 1 else 0)
    return v + geomSum

def generateSeries(s, n):
    r = DeterministicRng32(s)
    return "".join(str(r.randint(0, 8)) for _ in range(n))

def manipulateData(s, c):
    sStr = str(s); k = generateSeries(c, len(sStr))
    return "".join(chr(((ord(a) + ord(b) - 96) % 10) + 48) for a, b in zip(sStr, k))

def inverseData(s, c):
    sStr = str(s); k = generateSeries(c, len(sStr))
    return "".join(chr(((ord(a) - ord(b)) % 10) + 48) for a, b in zip(sStr, k))

def qRotate(s): return s[5:] + s[2:5][::-1] + s[:2]
def pRotate(s): return s[-2:] + s[-5:-2][::-1] + s[:-5]

def interject(s):
    s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, "")
    h = len(s) // 2
    return "".join(x + y for x, y in zip(s[:h], s[h:])) + p

def inverJect(s):
    s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, "")
    return "".join(s[i] for i in range(0, len(s), 2)) + "".join(s[i] for i in range(1, len(s), 2)) + p

def bSplit(s, f=4):
    bStr = binTail(s); l = len(bStr); rem = l % f
    res = ["1"]; res.extend(bStr[i:i+f][::-1] for i in range(0, l - rem, f))
    if rem: res.append(bStr[l-rem:])
    return int("".join(res), 2)

def kSplit(s, k):
    sBin = binTail(s); kStr = str(k).replace("0", "")
    if not kStr: return int("1" + sBin[::-1], 2)
    kDigits = [int(d) + 1 for d in kStr]
    kLen, sLen = len(kDigits), len(sBin)
    chunks, idx, kIdx = [], 0, 0
    while idx < sLen:
        step = kDigits[kIdx % kLen]
        chunks.append(sBin[idx: idx + step][::-1])
        idx += step; kIdx += 1
    return int("1" + "".join(chunks), 2)

def keySplit(n, k, y=1):
    m = str(k) if y == 1 else str(k)[::-1]
    for d in m: n = bSplit(n, int(d) + 2)
    return n

def baseSplit(n, k, b=8, y=1):
    m = 2 ** 16
    nDigits = fastAnyBaseList(n, b)
    z = [x for x in fastAnyBaseList(k, m) if 2 <= len(x) <= 10]
    if not z: z = [str((k % (m - 2)) + 2)]
    cap = (len(nDigits) + 2) * 40; loops = 0
    targetLen = len(nDigits) + 1 if y == 1 else len(nDigits)
    while len(z) < targetLen:
        nextK = int(z[-1]) + m
        z.extend(x for x in fastAnyBaseList(nextK, m) if 2 <= len(x) <= 10)
        loops += 1
        if loops > cap: break
    if len(z) < targetLen: z.extend([z[-1]] * (targetLen - len(z)))
    if y == 1:
        guard = (1 - (int(z[0]) % b)) % b
        nDigits = [str(guard)] + nDigits
        return fromAnyBase([str((int(x) + int(zv)) % b) for x, zv in zip(nDigits, z)], b)
    outDigits = [str((int(x) - int(zv)) % b) for x, zv in zip(nDigits, z)]
    return 0 if len(outDigits) <= 1 else fromAnyBase(outDigits[1:], b)

def Ap(n, m, p): return str(int(n) * int(m))[:p]
def Bp(n, p):
    n0 = ord(n[0]) - 48
    return "".join(chr(((ord(n[i % len(n)]) - 48 + n0) % 10) + 48) for i in range(p))
def Cp(n, m, p): return str(int(n) * int(n[:3 % len(n)]))[:p]
def Dp(n, m, p):
    ln, lm = len(n), len(m)
    return ("".join(str(abs((ord(n[i % ln]) - 48) * (ord(m[i % lm]) - 48))) for i in range(p)))[:p]

def Ep(n, p):
    ln = len(n)
    total = 0
    for i in range(p):
        a = (ord(n[i % ln]) - 48) + 1
        b = (ord(n[(i + 1) % ln]) - 48) + 1
        v = math.pi * (1 / a / b)
        token = str(v - int(v))[2:]
        total += int(token)
    return str(total)[-p:]

def processKey(n, m=0):
    n, m = str(n), str(m) if m else str(n)
    p, r = len(n), int(n[0])
    t = int(n[int(m[int(n[0])]) % p]) if len(m) > int(n[0]) else int(n[-1])
    a, b = (r + t) % 6, (r - t) % 6
    n = Ap(n, m, p) if a == 0 else Bp(n, p) if a == 1 else Cp(n, m, p) if a == 2 else Dp(n, m, p) if a == 3 else Ep(n, p) if a == 4 else Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p)
    n = Cp(n, m, p) if b == 0 else Dp(n, m, p) if b == 1 else Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p) if b == 2 else Bp(n, p) if b == 3 else Ap(n, m, p) if b == 4 else Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p)
    a, b = next((x for x in n if x.isdigit() and x != "0"), "2"), next((x for x in n[1:] if x.isdigit() and x != "0"), "3")
    n = str(bSplit(bSplit(int(n) + int(pRotate(n)))))
    n = tDecimal(qRotate(str(n)), 10)
    return str(int(int(n) + int(a + b + "0" * (p - 2))) + int(m))[-p:]

def checkData(n, i):
    while n < ten79: n *= 3; n, i = n + i, i + i
    s = str(n); n = sum(int(s[j:j+80]) for j in range(0, len(s), 80))
    return kSplit((int(qRotate(str(bSplit(n))) + processKey(n))), n)

def fold64(h):
    h = "".join(c for c in h.lower() if c in "0123456789abcdef")
    if not h: return "0" * 64
    if len(h) < 64: return h * ((64 // len(h)) + 1)
    out = [0] * 64
    for i, ch in enumerate(h): out[i % 64] ^= int(ch, 16)
    return "".join("0123456789abcdef"[x] for x in out)

def getE(hex64):
    x = hex64.lower().zfill(64)[-64:]
    s4 = (str(int(x[:4], 16) + int(x[-4:], 16)).lstrip("0") or "0")[:4]
    n = int(s4)
    if n < 4096: return n
    if n % 2 == 0: return int(s4[:-1]) + (100 if len(s4) > 1 and s4[-2] == "0" else 0)
    return int(s4[1:]) + (100 if len(s4) > 1 and s4[1] == "0" else 0)

def getB(hexStr):
    h = fold64(hexStr)
    f = int(h[:4], 16); l = int(h[-4:], 16)
    seedVal = ((f >> 8) ^ (l & 0xFF) ^ (f & 0xFF) ^ (l >> 8)) & 0xFF
    mh = "".join(f"{((int(h[i:i+2], 16) - seedVal) & 0xFF):02x}" for i in range(0, 64, 2))
    mh = hexLower(int(mh, 16) + int(h, 16))
    baseParam = int(mh[:4].zfill(4), 16); nVal = int(mh, 16); kVal = int(mh[-4:].zfill(4), 16)
    splitVal = baseSplit(nVal, kVal, b=(baseParam & 4096) + 64, y=1)
    splitHex = hexLower(splitVal)
    sFull = hexLower(int(h, 16) + int(splitHex, 16))
    s = fold64(sFull)
    return s, getE(s)

def manipulateKey(n):
    return fDecimal(tDecimal(hexLower(n), 16) + int(fDecimal(n, 16), 16), 16)[-63:-1]

def getKey(n, x=78):
    while True:
        n = (n // 8) + int(Ep(str(n // 5), len(str(n))))
        s = str(n)
        if len(s) <= x: return s

def hashKey(n): return getB(fetchKey(n))
def fetchKey(n): return manipulateKey(tDecimal(manipulateData(getKey(checkData(n + 90, (n % 7) + 1), 79), n), 10))

def pData(n, keys, b):
    for key in keys:
        n = keySplit(n, key, 1)
        n = tDecimal(str(manipulateData(str(n), key)), 10)
        n = baseSplit(int(n), key, b, 1)
        n = kSplit(n, str(key))
        if int(str(key)[0]) % 2 == 1: n = int(interject(str(n)))
    return n

def dData(n, keys, b):
    for key in reversed(keys):
        if int(str(key)[0]) % 2 == 1: n = int(inverJect(str(n)))
        n = kSplit(n, str(key))
        n = fDecimal(baseSplit(int(n), key, b, 0), 10)
        n = inverseData(n, key)
        n = keySplit(int(n), key, 0)
    return n

def encryptData(n, k=0):
    if not isinstance(n, str):
        raise ValueError("encryptData expects a string")
    if _plainSizeBytes(n) <= 2048:
        n = toBytes(n)
        if k:
            if not isHex64(k): raise ValueError("personalKey must be exactly 64 hex digits")
            hKey = k.lower()
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
    if k:
        if not isHex64(k): raise ValueError("personalKey must be exactly 64 hex digits")
        hKey = k.lower()
    else:
        hKey = shepKeyFromString(n)
    rawBytes = n.encode("utf-16-le", errors="surrogatepass")
    compBytes = zlib.compress(rawBytes, 9)
    parts = _chunkBytes(compBytes, 2048)
    totalSteps = len(parts) + 3
    done = 0
    cipherParts = []
    lens = []
    for p in parts:
        done += 1
        _printProg("ENC", done, totalSteps)
        cPart = _encryptIntWithKey(_toBytesBin(p), hKey)
        cipherParts.append(cPart)
        lens.append(len(cPart))
    joinedCipher = "".join(cipherParts)
    header = _buildHeader(2048, len(rawBytes), len(compBytes), lens)
    payload = header + joinedCipher
    mixed = _obfuscateProg(payload, hKey, 64, "ENC", done, totalSteps)
    return mixed, hKey

def decryptData(n, k):
    if not isHex64(k): raise ValueError("personalKey must be exactly 64 hex digits")
    k = k.lower()
    if isinstance(n, str):
        payloadGuess = None
        try:
            payloadGuess = deobfuscate(n, k, 64)
        except Exception:
            payloadGuess = None
        if payloadGuess and payloadGuess.startswith("shz1") and "a0a0" in payloadGuess:
            header, body, chunkSize, origLen, compLen, lens = _parseHeader(payloadGuess)
            totalSteps = len(lens) + 3
            done = 0
            payload = _deobfuscateProg(n, k, 64, "DEC", done, totalSteps)
            header, body, chunkSize, origLen, compLen, lens = _parseHeader(payload)
            compOut = bytearray()
            pos = 0
            for L in lens:
                done += 1
                _printProg("DEC", done, totalSteps)
                cPart = body[pos:pos + L]
                pos += L
                pInt = _decryptIntWithKey(cPart, k)
                compOut.extend(_fromBytesBin(pInt))
            if len(compOut) != compLen:
                raise ValueError("compressed length mismatch")
            rawBytes = zlib.decompress(bytes(compOut))
            if len(rawBytes) != origLen:
                raise ValueError("original length mismatch")
            return rawBytes.decode("utf-16-le", errors="surrogatepass")
    e = getE(k)
    key0 = tDecimal(k, 16)
    b = e
    n = tDecimal(n, 62)
    keys = [key0]
    key = key0
    for _ in range(9):
        key = int(processKey(key))
        keys.append(key)

    n = dData(n, keys, b)
    n = n - (key // b)
    return fromBytes(n)

def shepKeyFromString(s): return hashKey(toBytes(s))[0].lower()

def generatePKey(n=0):
    if isinstance(n, str):
        return hashKey(toBytes(n))[0].lower()
    chars = gChar(62)
    seedVal = int.from_bytes(os.urandom(32), "big") ^ time.time_ns()
    r = DeterministicRng32(seedVal)
    ln = r.randint(64, 256)
    s = [chars[r.randBelow(62)] for _ in range(ln)]
    r.shuffle(s)
    base62 = "".join(s)
    return hashKey(tDecimal(base62, 62))[0].lower()

# =========================
# CLI HELPERS
# =========================

import json

VERSION = "1.0.1"

DOC_EXTS = {".pdf", ".doc", ".docx", ".txt", ".rtf", ".odt", ".md", ".csv", ".xls", ".xlsx", ".json", ".tsv"}
ALLOWED_DEC_EXTS = {".shep32", ".sh3", ".sh32", ""}

KEY_HEADER = "-----BEGIN SHEP32 KEY-----\n"
KEY_FOOTER = "\n-----END SHEP32 KEY-----"

META_HEADER = b"SHEP32FILEv1\n"
META_DELIM = b"\n---\n"

DEFAULT_MAX_BYTES = 1000 * 1024

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

    return ""  # empty means "auto-key" path

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

def emitJson(obj):
    print(json.dumps(obj, ensure_ascii=False))

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

    # Plaintext path
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

    # 1) As entered (after ~ and env expansion.)
    variants.append(p)

    # 2) Relative to CWD if not absolute.
    if not p.is_absolute():
        variants.append(Path.cwd() / p)

    # 3) Relative to HOME if not absolute.
    home = Path.home()
    if not p.is_absolute():
        variants.append(home / p)
        
    # 4) If user typed like "docs/example.md" and the folder exists under HOME, try that
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

    mnt = Path("/mnt") # WSL common mount (harmless if missing.)
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

import difflib

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

        # Score components (stem matters most; ext helps)
        sStem = _sim(targetStem.lower(), candStem.lower())
        sName = _sim(targetName.lower(), fn.lower())

        # Prefer same extension when user supplied one
        extBonus = 0.0
        if targetExt:
            extBonus = 0.12 if candExt.lower() == targetExt.lower() else -0.08

        # Prefer closer directory to root slightly (keeps results sane)
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

    # 1) If user gave a parent dir that exists, search there first (tightest intent)
    try:
        if p.parent and existingDir(p.parent):
            roots.append(p.parent)
    except Exception:
        pass

    # 2) CWD and HOME next
    roots.extend(bestEffortSearchRoots())

    # Dedup roots
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

    # Fuzzy search: tight roots first, then broader
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
# WIZARD and EXCEPTIONS
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
# MAIN
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