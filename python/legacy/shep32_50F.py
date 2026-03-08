# =========================
# Main imports and runtime
# Build Version: 50F
# NOTES: Standard-library dependencies required for transforms, progress output, compression, and deterministic RNG support.
# =========================

import math, os, sys, time, zlib

# =========================
# Core constants and general helpers
# Build Version: 50F
# NOTES: Shared character sets, caches, lightweight validation, progress helpers, and small formatting utilities.
# =========================

tDecCache = {}

gPortableCounter = 0

sys.set_int_max_str_digits(0)

gCharBase = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:;<>?@[]^&()*$%/\\`\"',_!#"
def gChar(c): return gCharBase[:c]

def splitWs(s): return s.split()
def hexLower(n): return format(int(n), "x")

def isHex64(k):
    if not isinstance(k, str) or len(k) != 64: return False
    for ch in k:
        o = ord(ch)
        if not (48 <= o <= 57 or 65 <= o <= 70 or 97 <= o <= 102):
            return False
    return True

def binTail(n):
    b = format(int(n), "b")
    return "" if len(b) <= 1 else b[1:]

def _printProg(label, i, total):
    if total <= 0: return
    pct = int((i * 100) / total)
    sys.stdout.write(f"\r{label} {i}/{total} ({pct}%)")
    sys.stdout.flush()
    if i >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()

def _plainSizeBytes(s):
    return 1 + len(s.encode("utf-16-le", errors="surrogatepass"))

def _sepChar(i):
    a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return a[i % len(a)]

def _mix64(x):
    x &= 0xFFFFFFFFFFFFFFFF
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 31
    return x & 0xFFFFFFFFFFFFFFFF

def _portableSeed(extra=0):
    global gPortableCounter
    gPortableCounter += 1
    a = time.time_ns() & 0xFFFFFFFFFFFFFFFF
    b = time.perf_counter_ns() & 0xFFFFFFFFFFFFFFFF
    c = time.process_time_ns() & 0xFFFFFFFFFFFFFFFF
    d = int(extra) & 0xFFFFFFFFFFFFFFFF
    e = gPortableCounter & 0xFFFFFFFFFFFFFFFF
    x = _mix64(a ^ (b << 7) ^ (c << 13) ^ (d << 19) ^ e)
    y = _mix64((a << 17) ^ b ^ (c << 29) ^ d ^ (e << 11))
    return (x << 64) | y

def _portableHex(r, n=32):
    h = "0123456789abcdef"
    return "".join(h[r.randBelow(16)] for _ in range(n))

# =========================
# Deterministic RNG engine
# Build Version: 50F
# NOTES: Python-compatible MT19937-style deterministic random generator used by digit-series transforms.
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
# Permutation and obfuscation machinery
# Build Version: 50F
# NOTES: Hex parsing, seed derivation, deterministic permutation, and progress-aware wrappers for chunked payload mixing.
# =========================

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

def obfuscate(text, keyHex):
    steps = len(str(keyHex))
    seeds = deriveSeeds(keyHex, steps)
    t = text
    for s in seeds:
        t = permuteBySeed(t, s)
    return t

def deobfuscate(obfText, keyHex):
    steps = len(str(keyHex))
    seeds = deriveSeeds(keyHex, steps)
    t = obfText
    for s in reversed(seeds):
        t = unpermuteBySeed(t, s)
    return t

def _obfuscateProg(text, keyHex, steps, baseLabel, done, total):
    if steps != 64:
        _printProg(baseLabel, done + 1, total)
        return obfuscate(text, keyHex)

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
        return deobfuscate(obfText, keyHex)

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

# =========================
# Chunking, byte conversion, and payload framing
# Build Version: 50F
# NOTES: Raw byte sentinel helpers, chunk splitting, payload header construction/parsing, and per-chunk integer encryption wrappers.
# =========================

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

def _buildPrefix(saltHex, nonceHex, ivHex):
    vals = [str(saltHex).lower(), str(nonceHex).lower(), str(ivHex).lower()]
    for h in vals:
        if len(h) != 32 or any(ch not in "0123456789abcdef" for ch in h):
            raise ValueError("invalid prefix hex")
    return "shz2|" + "|".join(vals) + "|"

def _parsePrefix(payload):
    if not isinstance(payload, str):
        raise ValueError("ciphertext must be a string")
    parts = payload.split("|", 4)
    if len(parts) != 5 or parts[0] != "shz2":
        raise ValueError("missing shz2 prefix")
    saltHex = parts[1].lower()
    nonceHex = parts[2].lower()
    ivHex = parts[3].lower()
    rest = parts[4]
    for h in (saltHex, nonceHex, ivHex):
        if len(h) != 32 or any(ch not in "0123456789abcdef" for ch in h):
            raise ValueError("invalid prefix hex")
    return saltHex, nonceHex, ivHex, rest

def _buildHeader(chunkSize, origLen, compLen, lens, tagHex):
    tagHex = str(tagHex).lower()
    if len(tagHex) != 64 or any(ch not in "0123456789abcdef" for ch in tagHex):
        raise ValueError("invalid tag hex")
    lensStr = ",".join(str(int(x)) for x in lens)
    return "hd2|" + "|".join([
        str(int(chunkSize)),
        str(int(origLen)),
        str(int(compLen)),
        str(int(len(lens))),
        lensStr,
        tagHex
    ]) + "|a0a0|"

def _parseHeader(payload):
    if not isinstance(payload, str) or not payload.startswith("hd2|"):
        raise ValueError("missing hidden header prefix")

    t = payload.find("|a0a0|")
    if t == -1:
        raise ValueError("missing hidden header terminator")

    header = payload[:t + 6]
    body = payload[t + 6:]
    parts = payload[:t].split("|")

    if len(parts) != 7 or parts[0] != "hd2":
        raise ValueError("bad hidden header")

    chunkSize = int(parts[1])
    origLen = int(parts[2])
    compLen = int(parts[3])
    total = int(parts[4])
    lens = [] if not parts[5] else [int(x) for x in parts[5].split(",")]
    tagHex = parts[6].lower()

    if chunkSize <= 0 or origLen < 0 or compLen < 0 or total < 0:
        raise ValueError("invalid hidden header values")
    if total != len(lens):
        raise ValueError("chunk count mismatch")
    if any(x < 0 for x in lens):
        raise ValueError("negative chunk length")
    if sum(lens) != len(body):
        raise ValueError("body length mismatch")
    if len(tagHex) != 64 or any(ch not in "0123456789abcdef" for ch in tagHex):
        raise ValueError("invalid tag hex")

    return header, body, chunkSize, origLen, compLen, lens, {
        "version": "shz2",
        "tagHex": tagHex
    }

def _softDecodeUtf16le(b):
    if len(b) & 1:
        b = b[:-1]
    return b.decode("utf-16-le", errors="surrogatepass")

def _splitEven(s, count):
    count = int(count)
    if count < 1:
        count = 1
    n = len(s)
    q, r = divmod(n, count)
    out = []
    i = 0
    for j in range(count):
        step = q + (1 if j < r else 0)
        out.append(s[i:i + step])
        i += step
    return out

def _fromBytesBinSoft(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if not b:
        return b""
    if b[0] == 1:
        return b[1:]
    i = 0
    while i < len(b) and b[i] == 0:
        i += 1
    if i < len(b) and b[i] == 1:
        return b[i + 1:]
    return b[1:] if len(b) > 1 else b

def _looksZlib(b):
    if len(b) < 2:
        return False
    cmf = b[0]
    flg = b[1]
    if (cmf & 0x0F) != 8:
        return False
    if (cmf >> 4) > 7:
        return False
    return ((cmf << 8) + flg) % 31 == 0

def _softHeader(payload):
    out = {
        "body": payload if isinstance(payload, str) else "",
        "chunkSize": 2048,
        "origLen": 0,
        "compLen": 0,
        "lens": [],
        "hasHeader": False,
        "version": "",
        "tagHex": ""
    }

    if isinstance(payload, str):
        try:
            header, body, chunkSize, origLen, compLen, lens, meta = _parseHeader(payload)
            out["body"] = body
            out["chunkSize"] = chunkSize
            out["origLen"] = origLen
            out["compLen"] = compLen
            out["lens"] = lens
            out["hasHeader"] = True
            out["version"] = meta["version"]
            out["tagHex"] = meta["tagHex"]
            return out
        except Exception:
            pass

    guessCount = (len(out["body"]) + out["chunkSize"] - 1) // out["chunkSize"]
    if guessCount < 1:
        guessCount = 1
    out["lens"] = [len(x) for x in _splitEven(out["body"], guessCount)]
    return out

def _safeTextFromBytes(b):
    if len(b) & 1:
        b = b[:-1]
    s = b.decode("utf-16-le", errors="replace")
    return "".join("\uFFFD" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in s)
    
# =========================
# Encoding/Decoding functions
# Build Version: 50F
# NOTES: Functions used only by the encryption/decryption path.
# =========================

def _fixedEq(a, b):
    a = "" if a is None else str(a)
    b = "" if b is None else str(b)
    x = len(a) ^ len(b)
    m = max(len(a), len(b))
    for i in range(m):
        ca = ord(a[i]) if i < len(a) else 0
        cb = ord(b[i]) if i < len(b) else 0
        x |= ca ^ cb
    return x == 0

def _deriveMsgKeys(masterHex, saltHex, nonceHex, ivHex):
    seedA = fold64(masterHex + saltHex + nonceHex + ivHex)
    seedB = fold64(ivHex + nonceHex + saltHex + masterHex)
    encRoot = getB(seedA + seedB)[0].lower()
    authRoot = getB(seedB + seedA)[0].lower()
    return encRoot, authRoot

def _deriveChunkKey(encRoot, chunkIndex, saltHex, nonceHex, ivHex):
    idxHex = hexLower(int(chunkIndex)).zfill(16)[-16:]
    mix = fold64(encRoot + saltHex + nonceHex + ivHex + idxHex)
    return getB(mix + encRoot + idxHex)[0].lower()

def _makeAuthTag(authRoot, chunkSize, origLen, compLen, lens, saltHex, nonceHex, ivHex, body):
    metaHex = (
        hexLower(int(chunkSize)).zfill(8) +
        hexLower(int(origLen)).zfill(16) +
        hexLower(int(compLen)).zfill(16) +
        hexLower(len(lens)).zfill(8) +
        "".join(hexLower(int(x)).zfill(8) for x in lens) +
        saltHex + nonceHex + ivHex
    )

    state = getB(fold64(authRoot + metaHex))[0].lower()
    step = 256
    partCount = 0

    for i in range(0, len(body), step):
        part = body[i:i + step]
        partHex = hexLower(toBytes(part))
        idxHex = hexLower(partCount).zfill(8)
        lnHex = hexLower(len(part)).zfill(8)
        state = getB(fold64(state + authRoot + idxHex + lnHex + partHex))[0].lower()
        partCount += 1

    return getB(fold64(state + authRoot + hexLower(partCount).zfill(8)))[0].lower()

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

def inverseData(s, c):
    sStr = str(s); k = generateSeries(c, len(sStr))
    return "".join(chr(((ord(a) - ord(b)) % 10) + 48) for a, b in zip(sStr, k))

def interject(s):
    s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, "")
    h = len(s) // 2
    return "".join(x + y for x, y in zip(s[:h], s[h:])) + p

def inverJect(s):
    s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, "")
    return "".join(s[i] for i in range(0, len(s), 2)) + "".join(s[i] for i in range(1, len(s), 2)) + p

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
    
# =========================
# Shared functions
# Build Version: 50F
# NOTES: Common transforms used by both the hash-key derivation path and the encryption/decryption path.
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

def qRotate(s): return s[5:] + s[2:5][::-1] + s[:2]
def pRotate(s): return s[-2:] + s[-5:-2][::-1] + s[:-5]

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
    tbl = getattr(Ep, "tbl", None)
    if tbl is None:
        tbl = [[0] * 10 for _ in range(10)]
        for a in range(10):
            for b in range(10):
                v = math.pi / ((a + 1) * (b + 1))
                tbl[a][b] = int(str(v - int(v))[2:])
        Ep.tbl = tbl

    s = n if isinstance(n, str) else str(n)
    ln = len(s)
    total = 0

    for i in range(p):
        total += tbl[ord(s[i % ln]) - 48][ord(s[(i + 1) % ln]) - 48]

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

def getE(hex64):
    x = hex64.lower().zfill(64)[-64:]
    s4 = (str(int(x[:4], 16) + int(x[-4:], 16)).lstrip("0") or "0")[:4]
    n = int(s4)
    if n < 4096: return n
    if n % 2 == 0: return int(s4[:-1]) + (100 if len(s4) > 1 and s4[-2] == "0" else 0)
    return int(s4[1:]) + (100 if len(s4) > 1 and s4[1] == "0" else 0)

# =========================
# Hash-only key derivation and generation
# Build Version: 50F
# NOTES: Functions unique to the personal-key hashing/generation path. These are not part of the main forward/reverse encryption transform pipeline, but are used to derive or generate hash-based keys.
# =========================

def checkData(n, i=10):
    if not isinstance(n, int) or not isinstance(i, int): raise TypeError("n and i must be int")
    if n < 0 or i < 0: raise ValueError("n and i must be >= 0")

    n += 32
    ln = len(str(n))
    ten79 = 10 ** 79

    while n < ten79:
        n *= 3
        n, i = n + i, i + i

    i = 10 * (2 ** 163)
    n = int(str(n) + ("0" * 16) + str(ln))

    for _ in range(8):
        n *= 3
        n, i = n + i, i + i

    n = int(str(n * i) + ("0" * 8)) + i

    s = str(n)
    chunkBase = 10 ** 80
    packBase = 10 ** 82
    packed = len(s) + 1

    for j in range(0, len(s), 80):
        chunk = s[j:j + 80]
        packed = packed * packBase + (len(chunk) * chunkBase) + int(chunk)

    n = packed
    left = qRotate(str(bSplit(n)))
    right = processKey(n)
    mix = int("1" + str(len(left)).zfill(6) + left + right)

    return kSplit(mix, n)

def manipulateKey(n):
    return fDecimal(tDecimal(hexLower(n), 16) + int(fDecimal(n, 16), 16), 16)

def fold64(h):
    def rot(x, r):
        x &= m
        return ((x << r) | (x >> (64 - r))) & m

    def mix(x):
        x &= m
        x ^= x >> 32
        x = (x * 0xD6E8FEB86659FD93) & m
        x ^= x >> 29
        x = (x * 0xA5A3564E27F8862D) & m
        x ^= x >> 32
        return x & m

    def word(b, i):
        return (
            b[i]
            | (b[i + 1] << 8)
            | (b[i + 2] << 16)
            | (b[i + 3] << 24)
            | (b[i + 4] << 32)
            | (b[i + 5] << 40)
            | (b[i + 6] << 48)
            | (b[i + 7] << 56)
        ) & m

    m = 0xFFFFFFFFFFFFFFFF
    s = str(h).encode("utf-8")
    n = len(s)

    data = bytearray(s)
    data.append(0x80)
    while len(data) % 64 != 48:
        data.append(0)

    bitLen = (n * 8) & m
    lenMix = mix(bitLen ^ 0x9E3779B97F4A7C15 ^ n ^ 64)

    for i in range(8):
        data.append((bitLen >> (8 * i)) & 0xFF)
    for i in range(8):
        data.append((lenMix >> (8 * i)) & 0xFF)

    a = 0x243F6A8885A308D3 ^ mix(bitLen ^ 0x01)
    b = 0x13198A2E03707344 ^ mix(bitLen ^ 0x02)
    c = 0xA4093822299F31D0 ^ mix(bitLen ^ 0x03)
    d = 0x082EFA98EC4E6C89 ^ mix(bitLen ^ 0x04)
    e = 0x452821E638D01377 ^ mix(bitLen ^ 0x05)
    f = 0xBE5466CF34E90C6C ^ mix(bitLen ^ 0x06)
    g = 0xC0AC29B7C97C50DD ^ mix(bitLen ^ 0x07)
    j = 0x3F84D5B5B5470917 ^ mix(bitLen ^ 0x08)

    off = 0
    while off < len(data):
        x0 = word(data, off)
        x1 = word(data, off + 8)
        x2 = word(data, off + 16)
        x3 = word(data, off + 24)
        x4 = word(data, off + 32)
        x5 = word(data, off + 40)
        x6 = word(data, off + 48)
        x7 = word(data, off + 56)

        v0 = mix(x0 ^ a ^ (off + 1) ^ n)
        v1 = mix(x1 ^ b ^ (off + 2) ^ n)
        v2 = mix(x2 ^ c ^ (off + 3) ^ n)
        v3 = mix(x3 ^ d ^ (off + 4) ^ n)
        v4 = mix(x4 ^ e ^ (off + 5) ^ n)
        v5 = mix(x5 ^ f ^ (off + 6) ^ n)
        v6 = mix(x6 ^ g ^ (off + 7) ^ n)
        v7 = mix(x7 ^ j ^ (off + 8) ^ n)

        w0 = mix(v0 ^ rot(v3, 17) ^ rot(v5, 41) ^ 0x9E3779B97F4A7C15)
        w1 = mix(v1 ^ rot(v4, 29) ^ rot(v6, 31) ^ 0xC2B2AE3D27D4EB4F)
        w2 = mix(v2 ^ rot(v5, 13) ^ rot(v7, 47) ^ 0x165667B19E3779F9)
        w3 = mix(v3 ^ rot(v6, 11) ^ rot(v0, 37) ^ 0x85EBCA77C2B2AE63)
        w4 = mix(v4 ^ rot(v7, 19) ^ rot(v1, 53) ^ 0x27D4EB2F165667C5)
        w5 = mix(v5 ^ rot(v0, 23) ^ rot(v2, 43) ^ 0x94D049BB133111EB)
        w6 = mix(v6 ^ rot(v1, 7) ^ rot(v3, 59) ^ 0xD6E8FEB86659FD93)
        w7 = mix(v7 ^ rot(v2, 31) ^ rot(v4, 27) ^ 0xA5A3564E27F8862D)

        w8 = mix(w0 ^ rot(w3, 17) ^ x4 ^ 0x243F6A8885A308D3)
        w9 = mix(w1 ^ rot(w4, 29) ^ x5 ^ 0x13198A2E03707344)
        w10 = mix(w2 ^ rot(w5, 41) ^ x6 ^ 0xA4093822299F31D0)
        w11 = mix(w3 ^ rot(w6, 11) ^ x7 ^ 0x082EFA98EC4E6C89)
        w12 = mix(w4 ^ rot(w7, 37) ^ x0 ^ 0x452821E638D01377)
        w13 = mix(w5 ^ rot(w0, 23) ^ x1 ^ 0xBE5466CF34E90C6C)
        w14 = mix(w6 ^ rot(w1, 7) ^ x2 ^ 0xC0AC29B7C97C50DD)
        w15 = mix(w7 ^ rot(w2, 31) ^ x3 ^ 0x3F84D5B5B5470917)

        w16 = mix(w0 ^ w5 ^ rot(w10, 9) ^ x1 ^ 0x9E3779B185EBCA87)
        w17 = mix(w1 ^ w6 ^ rot(w11, 21) ^ x2 ^ 0xC2B2AE3D27D4EB4F)
        w18 = mix(w2 ^ w7 ^ rot(w12, 33) ^ x3 ^ 0x165667B19E3779F9)
        w19 = mix(w3 ^ w0 ^ rot(w13, 45) ^ x4 ^ 0x85EBCA77C2B2AE63)
        w20 = mix(w4 ^ w1 ^ rot(w14, 57) ^ x5 ^ 0x27D4EB2F165667C5)
        w21 = mix(w5 ^ w2 ^ rot(w15, 13) ^ x6 ^ 0x94D049BB133111EB)
        w22 = mix(w6 ^ w3 ^ rot(w8, 25) ^ x7 ^ 0xD6E8FEB86659FD93)
        w23 = mix(w7 ^ w4 ^ rot(w9, 39) ^ x0 ^ 0xA5A3564E27F8862D)

        aa = a ^ w16
        bb = b ^ w17
        cc = c ^ w18
        dd = d ^ w19
        ee = e ^ w20
        ff = f ^ w21
        gg = g ^ w22
        jj = j ^ w23

        ks = [
            w0, w1, w2, w3, w4, w5, w6, w7,
            w8, w9, w10, w11, w12, w13, w14, w15,
            w16, w17, w18, w19, w20, w21, w22, w23
        ]

        for r in range(24):
            k0 = ks[r]
            k1 = ks[(r + 7) % 24]
            k2 = ks[(r + 13) % 24]
            k3 = ks[(r + 19) % 24]

            t0 = mix((aa + k0 + rot(bb ^ ee, 17) + rot(ff ^ jj, 9)) & m)
            t1 = mix((cc + k1 + rot(dd ^ ff, 29) + rot(gg ^ aa, 21)) & m)
            t2 = mix((ee + k2 + rot(ff ^ gg, 41) + rot(jj ^ cc, 33)) & m)
            t3 = mix((gg + k3 + rot(jj ^ aa, 11) + rot(bb ^ dd, 45)) & m)

            aa = mix(t0 ^ rot(t2, 13) ^ ee ^ k1)
            bb = rot((bb + t1 + k2 + gg) & m, 23)
            cc = mix(t1 ^ rot(t3, 31) ^ gg ^ k3)
            dd = rot((dd + t2 + k0 + aa) & m, 37)
            ee = mix(t2 ^ rot(t0, 19) ^ aa ^ k2)
            ff = rot((ff + t3 + k1 + cc) & m, 43)
            gg = mix(t3 ^ rot(t1, 53) ^ cc ^ k0)
            jj = rot((jj + t0 + k3 + ee) & m, 59)

            aa, cc, ee, gg = cc, ee, gg, aa
            bb, dd, ff, jj = ff, bb, jj, dd

        a = mix(a ^ aa ^ x0 ^ w13 ^ w21)
        b = mix(b ^ bb ^ x1 ^ w14 ^ w22)
        c = mix(c ^ cc ^ x2 ^ w15 ^ w23)
        d = mix(d ^ dd ^ x3 ^ w8 ^ w16)
        e = mix(e ^ ee ^ x4 ^ w9 ^ w17)
        f = mix(f ^ ff ^ x5 ^ w10 ^ w18)
        g = mix(g ^ gg ^ x6 ^ w11 ^ w19)
        j = mix(j ^ jj ^ x7 ^ w12 ^ w20)

        a, e = e, a
        b, f = f, b
        c, g = g, c
        d, j = j, d

        off += 64

    p = mix(a ^ c ^ e ^ g ^ 0x243F6A8885A308D3)
    q = mix(b ^ d ^ f ^ j ^ 0x13198A2E03707344)
    r = mix(a ^ b ^ e ^ f ^ 0xA4093822299F31D0)
    t = mix(c ^ d ^ g ^ j ^ 0x082EFA98EC4E6C89)
    u = mix(a ^ d ^ e ^ j ^ 0x452821E638D01377)
    v = mix(b ^ c ^ f ^ g ^ 0xBE5466CF34E90C6C)

    p = mix(p ^ rot(q, 17) ^ rot(u, 9) ^ 0x9E3779B97F4A7C15)
    q = mix(q ^ rot(r, 29) ^ rot(v, 21) ^ 0xC2B2AE3D27D4EB4F)
    r = mix(r ^ rot(t, 41) ^ rot(p, 33) ^ 0x165667B19E3779F9)
    t = mix(t ^ rot(u, 13) ^ rot(q, 45) ^ 0x85EBCA77C2B2AE63)
    u = mix(u ^ rot(v, 27) ^ rot(r, 39) ^ 0x27D4EB2F165667C5)
    v = mix(v ^ rot(p, 31) ^ rot(t, 51) ^ 0x94D049BB133111EB)

    p = mix(p ^ u ^ rot(v, 7))
    q = mix(q ^ v ^ rot(p, 11))
    r = mix(r ^ p ^ rot(q, 19))
    t = mix(t ^ q ^ rot(r, 23))

    return f"{p:016x}{q:016x}{r:016x}{t:016x}"

def getB(hexStr):
    h = str(hexStr).lower()
    if not h:
        h = "0"

    f = int(h[:4], 16) if len(h) >= 4 else int(h, 16)
    l = int(h[-4:], 16) if len(h) >= 4 else int(h, 16)
    seedVal = ((f >> 8) ^ (l & 0xFF) ^ (f & 0xFF) ^ (l >> 8)) & 0xFF

    if len(h) & 1:
        h2 = "0" + h
    else:
        h2 = h

    parts = []
    for i in range(0, len(h2), 2):
        parts.append(f"{((int(h2[i:i+2], 16) - seedVal) & 0xFF):02x}")

    mh = "".join(parts)
    mh = hexLower(int(mh, 16) + int(h, 16))

    baseParam = int(mh[:4], 16) if len(mh) >= 4 else int(mh, 16)
    nVal = int(mh, 16)
    kVal = int(mh[-4:], 16) if len(mh) >= 4 else int(mh, 16)

    splitVal = baseSplit(nVal, kVal, b=(baseParam & 4096) + 64, y=1)
    splitHex = hexLower(splitVal)

    s = fold64(h + mh + splitHex)
    return s, getE(s)

def hashKey(n):
    a = int(fetchKey(n) + hex(n)[2:], 16)
    return getB(fetchKey(a))

def getKey(n, x=78):
    while True:
        n = (n // 8) + int(Ep(str(n // 5), len(str(n))))
        s = str(n)
        if len(s) <= x: return s

def fetchKey(n): return manipulateKey(tDecimal(manipulateData(getKey(checkData(n + 90, (n % 7) + 1), 79), n), 10))

def generatePKey(n=None):
    if n is not None:
        return hashKey(toBytes(str(n)))[0].lower()

    chars = gChar(62)
    seedVal = int.from_bytes(os.urandom(32), "big") ^ time.time_ns()
    r = DeterministicRng32(seedVal)
    ln = r.randint(64, 256)
    s = [chars[r.randBelow(62)] for _ in range(ln)]
    r.shuffle(s)
    base62 = "".join(s)
    return hashKey(tDecimal(base62, 62))[0].lower()

# =========================
# Public encryption and decryption API
# Build Version: 50F
# NOTES: Explicit-key-only entry points for plaintext encryption/decryption. All inputs are always compressed, chunked, headered, and obfuscated regardless of size.
# =========================

def encryptData(n, k=0):
    if not isinstance(n, str):
        raise ValueError("encryptData expects a string")

    if k is None or k == 0 or (isinstance(k, str) and not k.strip()):
        hKey = generatePKey().lower()
    else:
        if not isinstance(k, str):
            raise ValueError("key/passphrase must be a string")
        k = k.strip()
        hKey = k.lower() if isHex64(k) else generatePKey(k).lower()

    msgSeed = _portableSeed((len(n) << 32) ^ len(hKey) ^ _plainSizeBytes(n))
    msgRng = DeterministicRng32(msgSeed)

    saltHex = _portableHex(msgRng, 32)
    nonceHex = _portableHex(msgRng, 32)
    ivHex = _portableHex(msgRng, 32)

    encRoot, authRoot = _deriveMsgKeys(hKey, saltHex, nonceHex, ivHex)

    rawBytes = n.encode("utf-16-le", errors="surrogatepass")
    compBytes = zlib.compress(rawBytes, 9)
    parts = _chunkBytes(compBytes, 2048)

    totalSteps = len(parts) + 3
    done = 0

    cipherParts = []
    lens = []

    for idx, p in enumerate(parts):
        done += 1
        _printProg("ENC", done, totalSteps)
        chunkKey = _deriveChunkKey(encRoot, idx, saltHex, nonceHex, ivHex)
        cPart = _encryptIntWithKey(_toBytesBin(p), chunkKey)
        cipherParts.append(cPart)
        lens.append(len(cPart))

    joinedCipher = "".join(cipherParts)
    tagHex = _makeAuthTag(authRoot, 2048, len(rawBytes), len(compBytes), lens, saltHex, nonceHex, ivHex, joinedCipher)

    prefix = _buildPrefix(saltHex, nonceHex, ivHex)
    hiddenHeader = _buildHeader(2048, len(rawBytes), len(compBytes), lens, tagHex)
    privatePayload = hiddenHeader + joinedCipher

    mixed = _obfuscateProg(privatePayload, hKey, 64, "ENC", done, totalSteps)
    return prefix + mixed, hKey

def decryptData(n, k):
    if not isinstance(n, str):
        raise ValueError("decryptData expects a string ciphertext")
    if not isinstance(k, str):
        raise ValueError("key/passphrase must be a string")

    k = k.strip()
    if not k:
        raise ValueError("decryptData requires a key or passphrase")

    hKey = k.lower() if isHex64(k) else generatePKey(k).lower()

    saltHex, nonceHex, ivHex, obfPayload = _parsePrefix(n)
    encRoot, authRoot = _deriveMsgKeys(hKey, saltHex, nonceHex, ivHex)

    metaGuess = _softHeader(obfPayload)
    totalSteps = len(metaGuess["lens"]) + 3
    if totalSteps < 4:
        totalSteps = 4

    done = 0
    payload = _deobfuscateProg(obfPayload, hKey, 64, "DEC", done, totalSteps)
    done += 3

    meta = _softHeader(payload)
    body = meta["body"]
    lens = meta["lens"]

    compOut = bytearray()
    pos = 0
    bad = not meta["hasHeader"]

    for idx, L in enumerate(lens):
        done += 1
        _printProg("DEC", done, totalSteps)
        cPart = body[pos:pos + L]
        pos += L

        pInt = None
        try:
            chunkKey = _deriveChunkKey(encRoot, idx, saltHex, nonceHex, ivHex)
            pInt = _decryptIntWithKey(cPart, chunkKey)
            compOut.extend(_fromBytesBin(pInt))
        except Exception:
            bad = True
            try:
                if pInt is None:
                    pInt = _decryptIntWithKey(cPart, chunkKey)
                compOut.extend(_fromBytesBinSoft(pInt))
            except Exception:
                fallback = cPart.encode("utf-16-le", errors="surrogatepass")
                compOut.extend(fallback[:max(2, min(64, len(fallback)))])

    if pos != len(body):
        bad = True

    rawBytes = bytes(compOut)

    if meta["hasHeader"]:
        if meta["compLen"] > 0:
            rawBytes = rawBytes[:meta["compLen"]]

        try:
            if _looksZlib(rawBytes):
                rawBytes = zlib.decompress(rawBytes)
            else:
                bad = True
        except Exception:
            bad = True

        if meta["origLen"] > 0:
            rawBytes = rawBytes[:meta["origLen"]]

        expectTag = _makeAuthTag(
            authRoot,
            meta["chunkSize"],
            meta["origLen"],
            meta["compLen"],
            lens,
            saltHex,
            nonceHex,
            ivHex,
            body
        )

        if not _fixedEq(expectTag, meta["tagHex"]):
            bad = True

    if bad:
        raise ValueError("wrong key or damaged ciphertext")

    return _safeTextFromBytes(rawBytes)