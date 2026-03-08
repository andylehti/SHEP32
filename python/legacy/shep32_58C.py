
# =========================
# Main imports and runtime
# Build Version: 58C
# NOTES: Standard-library dependencies required for transforms, progress output, compression, and deterministic RNG support.
# =========================

import math, os, sys, time, zlib

# =========================
# Core constants and general helpers
# Build Version: 58C
# NOTES: Shared character sets, caches, lightweight validation, progress helpers, and small formatting utilities.
# =========================

tDecCache = {}
gPortableCounter = 0

sys.set_int_max_str_digits(0)

gCharBase = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:;<>?@[]^&()*$%/\\`\"',_!#"
gAuxBase = "ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
gSepBase = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

gTailSpec = {
    "ver": 2,
    "mode": 3,
    "suite": 2,
    "kdf": 2,
    "mac": 2,
    "flags": 3,
    "chunk": 4,
    "orig": 15,
    "comp": 15,
    "count": 5,
    "seed": 39,
    "tag": 78,
    "len": 5,
}

def deriveCharset(c): return gCharBase[:c]
def extractTokens(s): return s.split()
def encodeHex(n): return format(int(n), "x")
def deriveAuxCharset(): return gAuxBase

def isHex64(k):
    if not isinstance(k, str) or len(k) != 64: return False
    for ch in k:
        o = ord(ch)
        if not (48 <= o <= 57 or 65 <= o <= 70 or 97 <= o <= 102):
            return False
    return True

def dropPrefixBit(n):
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

def measureUtfBytes(s):
    return 1 + len(s.encode("utf-16-le", errors="surrogatepass"))

def deriveSeparator(i):
    return gSepBase[i % len(gSepBase)]

def diffuseWord64(x):
    x &= 0xFFFFFFFFFFFFFFFF
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    x ^= x >> 31
    return x & 0xFFFFFFFFFFFFFFFF

def derivePortableSeed(extra=0):
    global gPortableCounter
    gPortableCounter += 1
    a = time.time_ns() & 0xFFFFFFFFFFFFFFFF
    b = time.perf_counter_ns() & 0xFFFFFFFFFFFFFFFF
    c = time.process_time_ns() & 0xFFFFFFFFFFFFFFFF
    d = int(extra) & 0xFFFFFFFFFFFFFFFF
    e = gPortableCounter & 0xFFFFFFFFFFFFFFFF
    x = diffuseWord64(a ^ (b << 7) ^ (c << 13) ^ (d << 19) ^ e)
    y = diffuseWord64((a << 17) ^ b ^ (c << 29) ^ d ^ (e << 11))
    return (x << 64) | y

def derivePortableHex(r, n=32):
    h = "0123456789abcdef"
    return "".join(h[r.boundValue(16)] for _ in range(n))

def deriveSecureSeed():
    return str(int.from_bytes(os.urandom(16), "big")).zfill(gTailSpec["seed"])

def deriveSecureSeparator():
    return gSepBase[os.urandom(1)[0] % len(gSepBase)]

def leftPad(v, w):
    return str(int(v)).zfill(int(w))

def truncatePrefix(v, n):
    s = str(v)
    n = int(n)
    if n <= 0: return ""
    if len(s) >= n: return s[:n]
    return s + ("0" * (n - len(s)))

# =========================
# Deterministic RNG engine
# Build Version: 58C
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
        self.initializeSeed(seedValue)

    def initializeSeed(self, seedValue):
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
        self.expandSeed(key)

    def initializeState(self, s):
        self.mt[0] = int(s) & 0xFFFFFFFF
        for i in range(1, self.n):
            self.mt[i] = (1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & 0xFFFFFFFF
        self.mti = self.n

    def expandSeed(self, initKey):
        self.initializeState(19650218)
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

    def generateWord(self):
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

    def generateBits(self, k):
        k = int(k)
        if k <= 0:
            return 0
        words = (k + 31) // 32
        x = 0
        for _ in range(words):
            x = (x << 32) | self.generateWord()
        extra = words * 32 - k
        if extra:
            x >>= extra
        return x

    def boundValue(self, n):
        n = int(n)
        if n <= 0:
            raise ValueError("n must be > 0")
        k = n.bit_length()
        while True:
            r = self.generateBits(k)
            if r < n:
                return r

    def randint(self, a, b):
        a = int(a); b = int(b)
        if a > b:
            raise ValueError("a must be <= b")
        return a + self.boundValue(b - a + 1)

    def shuffle(self, arr):
        for i in range(len(arr) - 1, 0, -1):
            j = self.boundValue(i + 1)
            arr[i], arr[j] = arr[j], arr[i]
        return arr

# =========================
# Permutation and obfuscation machinery
# Build Version: 58C
# NOTES: Hex parsing, seed derivation, deterministic permutation, and progress-aware wrappers for chunked payload mixing.
# =========================

def decodeNibble(c):
    o = ord(c)
    if 48 <= o <= 57: return o - 48
    if 97 <= o <= 102: return o - 87
    if 65 <= o <= 70: return o - 55
    raise ValueError("non-hex")

def decodeNibbles(h):
    if not isinstance(h, str) or len(h) != 64:
        raise ValueError("keyHex must be 64 hex chars")
    return [decodeNibble(c) for c in h]

def iterateState(x):
    return (48271 * (x % 2147483647)) % 2147483647

def computePermutation(n, s):
    lane = list(range(n))
    state = s or 1
    for idx in range(n - 1, 0, -1):
        state = iterateState(state)
        tap = state % (idx + 1)
        lane[idx], lane[tap] = lane[tap], lane[idx]
    return lane

def permuteBySeed(t, s):
    width = len(t)
    if width < 2: return t
    lane = computePermutation(width, s)
    return "".join(t[pos] for pos in lane)

def unpermuteBySeed(t, s):
    width = len(t)
    if width < 2: return t
    lane = computePermutation(width, s)
    inv = [0] * width
    for dst, src in enumerate(lane):
        inv[src] = dst
    return "".join(t[inv[pos]] for pos in range(width))

def deriveSeeds(keyHex, steps):
    keyLanes = decodeNibbles(keyHex)
    mod = 2147483647
    state = 1
    carry = 0
    sched = [0] * steps
    laneCount = len(keyLanes)
    for rnd in range(steps):
        lane = keyLanes[rnd % laneCount]
        state = (state * 131 + lane + 1) % mod
        carry = (carry + state + (rnd + 1) * 17) % mod
        sched[rnd] = carry or 1
    return sched

def obfuscate(text, keyHex):
    block = text
    for roundSeed in deriveSeeds(keyHex, len(str(keyHex))):
        block = permuteBySeed(block, roundSeed)
    return block

def deobfuscate(obfText, keyHex):
    block = obfText
    for roundSeed in reversed(deriveSeeds(keyHex, len(str(keyHex)))):
        block = unpermuteBySeed(block, roundSeed)
    return block

def obfuscateProgress(text, keyHex, steps, baseLabel, done, total):
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

def deobfuscateProgress(obfText, keyHex, steps, baseLabel, done, total):
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
# Build Version: 58C
# NOTES: Raw byte sentinel helpers, chunk splitting, one-string tail packing/parsing, and per-message seed expansion.
# =========================

def encodeSentinel(b):
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise ValueError("encodeSentinel expects bytes")
    bb = b"\x01" + bytes(b)
    return int.from_bytes(bb, "big")

def decodeSentinel(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if not b or b[0] != 1:
        raise ValueError("byte sentinel missing")
    return b[1:]

def recoverSentinel(n):
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

def splitByteBlocks(b, chunkSize=2048):
    if chunkSize <= 0:
        raise ValueError("chunkSize must be > 0")
    b = bytes(b)
    if not b:
        return [b""]
    return [b[i:i + chunkSize] for i in range(0, len(b), chunkSize)]

def verifyZlib(b):
    if len(b) < 2:
        return False
    cmf = b[0]
    flg = b[1]
    if (cmf & 0x0F) != 8:
        return False
    if (cmf >> 4) > 7:
        return False
    return ((cmf << 8) + flg) % 31 == 0

def decodeSafeText(b):
    if len(b) & 1:
        b = b[:-1]
    s = b.decode("utf-16-le", errors="replace")
    return "".join("\uFFFD" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in s)

def encodeSeed(msgSeedDec):
    return encodeHex(int(msgSeedDec)).zfill(32)[-32:]

def expandSeedState(msgSeedDec):
    msgSeedHex = encodeSeed(msgSeedDec)
    a = fold64("WRAP|SEED|A|" + msgSeedHex)
    b = fold64("WRAP|SEED|B|" + a + msgSeedHex)
    c = fold64("WRAP|SEED|C|" + b + a + msgSeedHex)
    saltHex = computeBound(a + b)[0].lower()[:32]
    nonceHex = computeBound(b + c)[0].lower()[:32]
    ivHex = computeBound(c + a)[0].lower()[:32]
    return saltHex, nonceHex, ivHex

def deriveWrapSeed():
    return deriveSecureSeed()

def pruneTail(s):
    if not isinstance(s, str) or not s:
        raise ValueError("ciphertext must be non-empty string")
    i = len(s)
    while i > 0 and s[i - 1].isdigit():
        i -= 1
    if i <= 0 or i >= len(s):
        raise ValueError("missing numeric tail")
    sep = s[i - 1]
    if sep not in gSepBase:
        raise ValueError("missing alpha delimiter")
    body = s[:i - 1]
    tail = s[i:]
    if not body:
        raise ValueError("missing body")
    return body, sep, tail

def loadTail(ver, mode, suite, kdfId, macId, flags, chunkSize, origLen, compLen, lens, msgSeedDec, tagHex):
    w = gTailSpec
    count = len(lens)
    if count < 1 or count >= 10 ** w["count"]:
        raise ValueError("invalid chunk count")
    if any(int(x) < 0 or int(x) >= 10 ** w["len"] for x in lens):
        raise ValueError("invalid chunk length")
    tagDec = str(int(str(tagHex), 16)).zfill(w["tag"])
    return "".join([
        leftPad(ver, w["ver"]),
        leftPad(mode, w["mode"]),
        leftPad(suite, w["suite"]),
        leftPad(kdfId, w["kdf"]),
        leftPad(macId, w["mac"]),
        leftPad(flags, w["flags"]),
        leftPad(chunkSize, w["chunk"]),
        leftPad(origLen, w["orig"]),
        leftPad(compLen, w["comp"]),
        leftPad(count, w["count"]),
        str(msgSeedDec).zfill(w["seed"]),
        tagDec,
        "".join(leftPad(x, w["len"]) for x in lens),
    ])

def parseTail(tail):
    if not isinstance(tail, str) or not tail.isdigit():
        raise ValueError("tail must be numeric")
    w = gTailSpec
    baseLen = w["ver"] + w["mode"] + w["suite"] + w["kdf"] + w["mac"] + w["flags"] + w["chunk"] + w["orig"] + w["comp"] + w["count"] + w["seed"] + w["tag"]
    if len(tail) < baseLen:
        raise ValueError("tail too short")
    i = 0
    def take(n):
        nonlocal i
        s = tail[i:i+n]
        if len(s) != n:
            raise ValueError("tail truncated")
        i += n
        return s
    ver = int(take(w["ver"]))
    mode = int(take(w["mode"]))
    suite = int(take(w["suite"]))
    kdfId = int(take(w["kdf"]))
    macId = int(take(w["mac"]))
    flags = int(take(w["flags"]))
    chunkSize = int(take(w["chunk"]))
    origLen = int(take(w["orig"]))
    compLen = int(take(w["comp"]))
    count = int(take(w["count"]))
    msgSeedDec = take(w["seed"])
    tagDec = take(w["tag"])
    need = count * w["len"]
    if len(tail) != baseLen + need:
        raise ValueError("tail length mismatch")
    lens = []
    for _ in range(count):
        lens.append(int(take(w["len"])))
    tagHex = encodeHex(int(tagDec)).zfill(64)[-64:]
    return {
        "ver": ver,
        "mode": mode,
        "suite": suite,
        "kdfId": kdfId,
        "macId": macId,
        "flags": flags,
        "chunkSize": chunkSize,
        "origLen": origLen,
        "compLen": compLen,
        "lens": lens,
        "msgSeedDec": msgSeedDec,
        "tagHex": tagHex,
    }

# =========================
# Shared transforms and state diffusion
# Build Version: 58C
# NOTES: Common transforms used by the derivation path and the encryption/decryption path.
# =========================

def encodeTextBlock(t):
    b = b"\x01" + str(t).encode("utf-16-le", errors="surrogatepass")
    return int.from_bytes(b, "big")

def decodeTextBlock(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if not b or b[0] != 1:
        raise ValueError("byte sentinel missing")
    return b[1:].decode("utf-16-le", errors="surrogatepass")

def computeRadixDigits(val, b):
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
        half = targetLen // 2
        divisor = b ** half
        upperVal, lowerVal = divmod(v, divisor)
        return convert(upperVal, targetLen - half) + convert(lowerVal, half)
    res = convert(val, n)
    while len(res) > 1 and res[0] == "0": res.pop(0)
    return res

def encodeRadixStream(n, b):
    return " ".join(computeRadixDigits(n, b))

def decodeRadixStream(n, b):
    parts = extractTokens(n) if isinstance(n, str) else n
    if not parts:
        return 0
    ints = [int(p) for p in parts]
    def evalRange(start, end):
        if end - start <= 200:
            res = 0
            for i in range(start, end):
                res = res * b + ints[i]
            return res
        mid = (start + end) // 2
        return evalRange(start, mid) * (b ** (end - mid)) + evalRange(mid, end)
    return evalRange(0, len(ints))

def encodeRadix(val, b, padTo, charset):
    if padTo <= 500:
        out = []
        for _ in range(padTo): out.append(charset[val % b]); val //= b
        return "".join(reversed(out))
    half = padTo // 2
    divisor = b ** half
    upperVal, lowerVal = divmod(val, divisor)
    return encodeRadix(upperVal, b, padTo - half, charset) + encodeRadix(lowerVal, b, half, charset)

def encodeShift(d, b):
    c = deriveCharset(b)
    if b == 1: return c[0] * (d + 1)
    target = d * (b - 1) + b
    powers = [(1, b)]
    while powers[-1][1] <= target: powers.append((powers[-1][0] * 2, powers[-1][1] ** 2))
    n = 0; curBn = 1
    for pN, pVal in reversed(powers):
        if curBn * pVal <= target: curBn *= pVal; n += pN
    geomSum = (b ** n - b) // (b - 1) if n > 0 else 0
    r = d - geomSum
    return "" if n == 0 else encodeRadix(r, b, n, c)

def decodeShift(c, b):
    s = str(c)
    l = len(s)
    if b == 10: return int(s) + ((10 ** l - 10) // 9 if l > 1 else 0)
    if b == 16: return int(s, 16) + ((16 ** l - 16) // 15 if l > 1 else 0)
    if b not in tDecCache: tDecCache[b] = {ch: i for i, ch in enumerate(deriveCharset(b))}
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

def generateKeystream(s, n):
    r = DeterministicRng32(s)
    return "".join(str(r.randint(0, 8)) for _ in range(n))

def diffuseSequence(s, c):
    state = str(s)
    keystream = generateKeystream(c, len(state))
    out = []
    for left, mask in zip(state, keystream):
        out.append(chr(((ord(left) + ord(mask) - 96) % 10) + 48))
    return "".join(out)

def recoverSequence(s, c):
    state = str(s)
    keystream = generateKeystream(c, len(state))
    out = []
    for left, mask in zip(state, keystream):
        out.append(chr(((ord(left) - ord(mask)) % 10) + 48))
    return "".join(out)

def permutePrefix(s): return s[5:] + s[2:5][::-1] + s[:2]
def permuteSuffix(s): return s[-2:] + s[-5:-2][::-1] + s[:-5]

def distributeBits(s, f=4):
    bitstream = dropPrefixBit(s)
    width = len(bitstream)
    rem = width % f
    lanes = ["1"]
    stop = width - rem
    idx = 0
    while idx < stop:
        lanes.append(bitstream[idx:idx + f][::-1])
        idx += f
    if rem:
        lanes.append(bitstream[stop:])
    return int("".join(lanes), 2)

def diffuseBits(s, k):
    bitstream = dropPrefixBit(s)
    keyText = str(k).replace("0", "")
    if not keyText: return int("1" + bitstream[::-1], 2)
    stride = [int(ch) + 1 for ch in keyText]
    out = []
    pos = 0
    turn = 0
    limit = len(bitstream)
    span = len(stride)
    while pos < limit:
        step = stride[turn % span]
        out.append(bitstream[pos:pos + step][::-1])
        pos += step
        turn += 1
    return int("1" + "".join(out), 2)

def partitionKey(n, k, y=1):
    schedule = str(k) if y == 1 else str(k)[::-1]
    state = n
    for lane in schedule:
        state = distributeBits(state, int(lane) + 2)
    return state

def distributeRadix(n, k, b=8, y=1):
    seedBase = 2 ** 16
    stateDigits = computeRadixDigits(n, b)
    schedule = [x for x in computeRadixDigits(k, seedBase) if 2 <= len(x) <= 10]
    if not schedule:
        schedule = [str((k % (seedBase - 2)) + 2)]
    limit = (len(stateDigits) + 2) * 40
    need = len(stateDigits) + 1 if y == 1 else len(stateDigits)
    loops = 0
    while len(schedule) < need:
        nextSeed = int(schedule[-1]) + seedBase
        schedule.extend(x for x in computeRadixDigits(nextSeed, seedBase) if 2 <= len(x) <= 10)
        loops += 1
        if loops > limit:
            break
    if len(schedule) < need:
        schedule.extend([schedule[-1]] * (need - len(schedule)))
    if y == 1:
        guard = (1 - (int(schedule[0]) % b)) % b
        stateDigits = [str(guard)] + stateDigits
        mixed = [str((int(a) + int(z)) % b) for a, z in zip(stateDigits, schedule)]
        return decodeRadixStream(mixed, b)
    mixed = [str((int(a) - int(z)) % b) for a, z in zip(stateDigits, schedule)]
    return 0 if len(mixed) <= 1 else decodeRadixStream(mixed[1:], b)

def interleaveStreams(s):
    state = str(s)
    if len(state) & 1:
        core = state[:-1]
        tail = state[-1]
    else:
        core = state
        tail = ""
    half = len(core) // 2
    left = core[:half]
    right = core[half:]
    out = []
    for a, b in zip(left, right):
        out.append(a)
        out.append(b)
    return "".join(out) + tail

def separateStreams(s):
    state = str(s)
    if len(state) & 1:
        core = state[:-1]
        tail = state[-1]
    else:
        core = state
        tail = ""
    even = []
    odd = []
    for idx, ch in enumerate(core):
        if (idx & 1) == 0:
            even.append(ch)
        else:
            odd.append(ch)
    return "".join(even) + "".join(odd) + tail

def decodeDigit(ch):
    return ord(ch) - 48

def computePiMatrix():
    box = getattr(computePiMatrix, "box", None)
    if box is None:
        box = [[0] * 10 for _ in range(10)]
        for i in range(10):
            for j in range(10):
                z = math.pi / ((i + 1) * (j + 1))
                box[i][j] = int(str(z - int(z))[2:])
        computePiMatrix.box = box
    return box

def prefixProduct(n, m, p):
    state = int(str(n))
    key = int(str(m))
    return str(state * key)[:p]

def biasTransform(n, p):
    state = str(n)
    width = len(state)
    seed = decodeDigit(state[0])
    out = []
    for i in range(p):
        lane = decodeDigit(state[i % width])
        out.append(chr(((lane + seed) % 10) + 48))
    return "".join(out)

def prefixSquare(n, m, p):
    state = str(n)
    tap = int(state[:3 % len(state)])
    return str(int(state) * tap)[:p]

def digitProduct(n, m, p):
    left = str(n)
    right = str(m)
    wl, wr = len(left), len(right)
    out = []
    for i in range(p):
        a = decodeDigit(left[i % wl])
        b = decodeDigit(right[i % wr])
        out.append(str(abs(a * b)))
    return "".join(out)[:p]

def integratePi(n, p):
    box = computePiMatrix()
    state = n if isinstance(n, str) else str(n)
    width = len(state)
    acc = 0
    for i in range(p):
        a = decodeDigit(state[i % width])
        b = decodeDigit(state[(i + 1) % width])
        acc += box[a][b]
    return str(acc)[-p:]

def executeCascade(state, key, width):
    return prefixProduct(
        biasTransform(
            prefixSquare(
                digitProduct(
                    integratePi(state, width),
                    key,
                    width
                ),
                key,
                width
            ),
            width
        ),
        key,
        width
    )

def processKey(n, m=0):
    state = str(n)
    key = str(m) if m else state
    width = len(state)
    seed = int(state[0])
    tap = int(state[int(key[seed]) % width]) if len(key) > seed else int(state[-1])

    routeA = (seed + tap) % 6
    routeB = (seed - tap) % 6

    state = prefixProduct(state, key, width) if routeA == 0 else biasTransform(state, width) if routeA == 1 else prefixSquare(state, key, width) if routeA == 2 else digitProduct(state, key, width) if routeA == 3 else integratePi(state, width) if routeA == 4 else executeCascade(state, key, width)
    state = prefixSquare(state, key, width) if routeB == 0 else digitProduct(state, key, width) if routeB == 1 else executeCascade(state, key, width) if routeB == 2 else biasTransform(state, width) if routeB == 3 else prefixProduct(state, key, width) if routeB == 4 else executeCascade(state, key, width)

    hi = next((ch for ch in state if ch.isdigit() and ch != "0"), "2")
    lo = next((ch for ch in state[1:] if ch.isdigit() and ch != "0"), "3")

    state = str(distributeBits(distributeBits(int(state) + int(permuteSuffix(state)))))
    state = decodeShift(permutePrefix(state), 10)

    mask = int(hi + lo + ("0" * (width - 2)))
    return str(int(int(state) + mask) + int(key))[-width:]

def deriveBaseFactor(hex64):
    x = hex64.lower().zfill(64)[-64:]
    s4 = (str(int(x[:4], 16) + int(x[-4:], 16)).lstrip("0") or "0")[:4]
    n = int(s4)
    if n < 4096: return n
    if n % 2 == 0: return int(s4[:-1]) + (100 if len(s4) > 1 and s4[-2] == "0" else 0)
    return int(s4[1:]) + (100 if len(s4) > 1 and s4[1] == "0" else 0)
# =========================
# Hash-only key derivation and generation
# Build Version: 58B
# NOTES: Functions unique to the personal-key hashing/generation path, plus deterministic standard and extended key generation.
# =========================

def traceWideState(n, i=10):
    if not isinstance(n, int) or not isinstance(i, int): raise TypeError("n and i must be int")
    if n < 0 or i < 0: raise ValueError("n and i must be >= 0")

    n += 32
    start = n
    ln = len(str(n))
    ten79 = 10 ** 79

    while n < ten79:
        n *= 3
        n, i = n + i, i + i
    first = n

    i = 10 * (2 ** 163)
    n = int(str(n) + ("0" * 16) + str(ln))
    firstPad = n

    for _ in range(8):
        n *= 3
        n, i = n + i, i + i
    second = n

    n = int(str(n * i) + ("0" * 8)) + i
    third = n

    s = str(n)
    chunkBase = 10 ** 80
    packBase = 10 ** 82
    packed = len(s) + 1
    for j in range(0, len(s), 80):
        chunk = s[j:j + 80]
        packed = packed * packBase + (len(chunk) * chunkBase) + int(chunk)

    packedLen = len(s)
    fourth = packed
    left = permutePrefix(str(distributeBits(fourth)))
    right = processKey(fourth)
    mix = int("1" + str(len(left)).zfill(6) + left + right)
    value = diffuseBits(mix, fourth)

    return {
        "input": start,
        "first": first,
        "firstPad": firstPad,
        "second": second,
        "third": third,
        "packedLen": packedLen,
        "fourth": fourth,
        "left": left,
        "mix": mix,
        "right": right,
        "value": value,
    }

def validateState(n, i=10):
    return traceWideState(n, i)["value"]

def diffuseKey(n):
    return encodeShift(decodeShift(encodeHex(n), 16) + int(encodeShift(n, 16), 16), 16)

def fold64(h):
    def rot(x, r):
        x &= m
        return ((x << r) | (x >> (64 - r))) & m

    def mix(x):
        x &= m
        x ^= x >> 31
        x = (x * 0x7FB5D329728EA185) & m
        x ^= x >> 27
        x = (x * 0x81DADEF4BC2DD44D) & m
        x ^= x >> 33
        x = (x * 0xD6E8FEB86659FD93) & m
        x ^= x >> 29
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
    data = bytearray(str(h).encode("utf-8"))
    n = len(data)
    bitLen = (n * 8) & m

    data.append(0x80)
    while len(data) % 128 != 112:
        data.append(0)

    lenA = mix(bitLen ^ n ^ 0x9E3779B97F4A7C15)
    lenB = mix(((bitLen << 1) ^ n ^ 0xC2B2AE3D27D4EB4F) & m)

    for i in range(8):
        data.append((bitLen >> (8 * i)) & 0xFF)
    for i in range(8):
        data.append((lenA >> (8 * i)) & 0xFF)
    for i in range(8):
        data.append((lenB >> (8 * i)) & 0xFF)

    while len(data) % 128 != 0:
        data.append(0)

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
        x0 = word(data, off + 0)
        x1 = word(data, off + 8)
        x2 = word(data, off + 16)
        x3 = word(data, off + 24)
        x4 = word(data, off + 32)
        x5 = word(data, off + 40)
        x6 = word(data, off + 48)
        x7 = word(data, off + 56)
        x8 = word(data, off + 64)
        x9 = word(data, off + 72)
        x10 = word(data, off + 80)
        x11 = word(data, off + 88)
        x12 = word(data, off + 96)
        x13 = word(data, off + 104)
        x14 = word(data, off + 112)
        x15 = word(data, off + 120)

        w0 = mix(x0 ^ a ^ x8 ^ 0x9E3779B97F4A7C15)
        w1 = mix(x1 ^ b ^ x9 ^ 0xC2B2AE3D27D4EB4F)
        w2 = mix(x2 ^ c ^ x10 ^ 0x165667B19E3779F9)
        w3 = mix(x3 ^ d ^ x11 ^ 0x85EBCA77C2B2AE63)
        w4 = mix(x4 ^ e ^ x12 ^ 0x27D4EB2F165667C5)
        w5 = mix(x5 ^ f ^ x13 ^ 0x94D049BB133111EB)
        w6 = mix(x6 ^ g ^ x14 ^ 0xD6E8FEB86659FD93)
        w7 = mix(x7 ^ j ^ x15 ^ 0xA5A3564E27F8862D)

        r = 0
        while r < 12:
            t0 = mix((a + w0 + rot(e ^ w4, 17) + rot(f ^ w5, 9)) & m)
            t1 = mix((b + w1 + rot(f ^ w5, 29) + rot(g ^ w6, 21)) & m)
            t2 = mix((c + w2 + rot(g ^ w6, 41) + rot(j ^ w7, 33)) & m)
            t3 = mix((d + w3 + rot(j ^ w7, 11) + rot(a ^ w0, 45)) & m)
            t4 = mix((e + w4 + rot(a ^ w0, 23) + rot(b ^ w1, 37)) & m)
            t5 = mix((f + w5 + rot(b ^ w1, 31) + rot(c ^ w2, 49)) & m)
            t6 = mix((g + w6 + rot(c ^ w2, 13) + rot(d ^ w3, 57)) & m)
            t7 = mix((j + w7 + rot(d ^ w3, 27) + rot(e ^ w4, 39)) & m)

            a = mix(t0 ^ rot(t3, 7) ^ w1)
            b = mix(t1 ^ rot(t4, 11) ^ w2)
            c = mix(t2 ^ rot(t5, 19) ^ w3)
            d = mix(t3 ^ rot(t6, 23) ^ w4)
            e = mix(t4 ^ rot(t7, 31) ^ w5)
            f = mix(t5 ^ rot(t0, 37) ^ w6)
            g = mix(t6 ^ rot(t1, 43) ^ w7)
            j = mix(t7 ^ rot(t2, 53) ^ w0)

            w0 = mix(w0 ^ a ^ rot(w4, 9))
            w1 = mix(w1 ^ b ^ rot(w5, 13))
            w2 = mix(w2 ^ c ^ rot(w6, 17))
            w3 = mix(w3 ^ d ^ rot(w7, 21))
            w4 = mix(w4 ^ e ^ rot(w0, 25))
            w5 = mix(w5 ^ f ^ rot(w1, 29))
            w6 = mix(w6 ^ g ^ rot(w2, 33))
            w7 = mix(w7 ^ j ^ rot(w3, 37))

            a, c, e, g = c, e, g, a
            b, d, f, j = f, b, j, d
            r += 1

        a = mix(a ^ x0 ^ x9 ^ w2)
        b = mix(b ^ x1 ^ x10 ^ w3)
        c = mix(c ^ x2 ^ x11 ^ w4)
        d = mix(d ^ x3 ^ x12 ^ w5)
        e = mix(e ^ x4 ^ x13 ^ w6)
        f = mix(f ^ x5 ^ x14 ^ w7)
        g = mix(g ^ x6 ^ x15 ^ w0)
        j = mix(j ^ x7 ^ x8 ^ w1)

        off += 128

    p = mix(a ^ c ^ e ^ g ^ 0x243F6A8885A308D3)
    q = mix(b ^ d ^ f ^ j ^ 0x13198A2E03707344)
    r = mix(a ^ b ^ e ^ f ^ 0xA4093822299F31D0)
    t = mix(c ^ d ^ g ^ j ^ 0x082EFA98EC4E6C89)

    p = mix(p ^ rot(q, 17) ^ rot(r, 31))
    q = mix(q ^ rot(r, 23) ^ rot(t, 41))
    r = mix(r ^ rot(t, 29) ^ rot(p, 37))
    t = mix(t ^ rot(p, 13) ^ rot(q, 47))

    return f"{p:016x}{q:016x}{r:016x}{t:016x}"

def computeBound(hexStr):
    h = str(hexStr).lower()
    if not h:
        h = "0"

    f = int(h[:4], 16) if len(h) >= 4 else int(h, 16)
    l = int(h[-4:], 16) if len(h) >= 4 else int(h, 16)
    seedVal = ((f >> 8) ^ (l & 0xFF) ^ (f & 0xFF) ^ (l >> 8)) & 0xFF

    h2 = "0" + h if len(h) & 1 else h

    parts = []
    for i in range(0, len(h2), 2):
        parts.append(f"{((int(h2[i:i+2], 16) - seedVal) & 0xFF):02x}")

    mh = "".join(parts)
    mh = encodeHex(int(mh, 16) + int(h, 16))

    baseParam = int(mh[:4], 16) if len(mh) >= 4 else int(mh, 16)
    nVal = int(mh, 16)
    kVal = int(mh[-4:], 16) if len(mh) >= 4 else int(mh, 16)

    splitVal = distributeRadix(nVal, kVal, b=(baseParam & 4096) + 64, y=1)
    splitHex = encodeHex(splitVal)

    s = fold64(h + mh + splitHex)
    return s, deriveBaseFactor(s)

def compressKey(n, width=78):
    while True:
        n = (n // 8) + int(integratePi(str(n // 5), len(str(n))))
        s = str(n)
        if len(s) <= width:
            return s

def deriveKeyState(n):
    seedState = validateState(n + 90, (n % 7) + 1)
    compactState = compressKey(seedState, 79)
    diffusedState = diffuseSequence(compactState, n)
    decodedState = decodeShift(diffusedState, 10)
    return diffuseKey(decodedState)

def computeKeyDigest(n):
    chainA = deriveKeyState(n)
    a = int(chainA + hex(n)[2:], 16)
    chainB = deriveKeyState(a)
    return computeBound(chainB)

def generateSeedSource():
    chars = deriveCharset(62)
    seedVal = int.from_bytes(os.urandom(32), "big") ^ time.time_ns()
    r = DeterministicRng32(seedVal)
    ln = r.randint(64, 256)
    s = [chars[r.boundValue(62)] for _ in range(ln)]
    r.shuffle(s)
    return "".join(s)

def normalizeSeedBytes(x):
    if isinstance(x, int):
        return str(x).encode("utf-16-le", errors="surrogatepass")
    if isinstance(x, str):
        return x.encode("utf-16-le", errors="surrogatepass")
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    raise TypeError("unsupported input type")

def normalizeSeedInput(x):
    return encodeSentinel(normalizeSeedBytes(x))

def computeKeyDigestStream(b, directBits=256, laneBits=336, blockBytes=4096):
    raw = bytes(b)
    directBytes = max(1, (int(directBits) + 7) // 8)
    laneBytes = max(directBytes + 1, (int(laneBits) + 7) // 8)
    blockBytes = max(laneBytes, int(blockBytes))

    if len(raw) <= directBytes:
        return computeKeyDigest(encodeSentinel(raw))[0].lower()

    totalLen = len(raw)
    head = raw[:directBytes]
    headDigest = computeKeyDigest(encodeSentinel(head))[0].lower()

    state = computeBound(
        fold64(
            "SHEP58A|KEY|STREAM|ROOT|"
            + str(directBits) + "|"
            + str(laneBits) + "|"
            + str(totalLen) + "|"
            + headDigest
        )
    )[0].lower()

    laneIndex = 0

    for blockOff in range(0, totalLen, blockBytes):
        block = raw[blockOff:blockOff + blockBytes]

        blockState = fold64(
            "SHEP58A|KEY|STREAM|BLOCK|"
            + state + "|"
            + str(blockOff) + "|"
            + str(len(block)) + "|"
            + str(totalLen)
        )

        for innerOff in range(0, len(block), laneBytes):
            lane = block[innerOff:innerOff + laneBytes]
            laneHex = encodeHex(encodeSentinel(lane))

            frameA = fold64(
                "SHEP58A|KEY|STREAM|LEAF|A|"
                + blockState + "|"
                + str(laneIndex) + "|"
                + str(len(lane)) + "|"
                + laneHex
            )

            frameB = fold64(
                "SHEP58A|KEY|STREAM|LEAF|B|"
                + state + "|"
                + headDigest + "|"
                + str(totalLen) + "|"
                + str(laneIndex)
            )

            blockState = computeBound(
                frameA
                + frameB
                + leftPad(laneIndex, 8)
                + leftPad(len(lane), 5)
                + leftPad(totalLen, 15)
            )[0].lower()

            laneIndex += 1

        state = computeBound(
            fold64(
                "SHEP58A|KEY|STREAM|BLOCK|FINAL|"
                + state + "|"
                + blockState + "|"
                + str(blockOff) + "|"
                + str(len(block)) + "|"
                + str(laneIndex)
            )
        )[0].lower()

    finalA = fold64(
        "SHEP58A|KEY|STREAM|FINAL|A|"
        + state + "|"
        + headDigest + "|"
        + str(totalLen) + "|"
        + str(laneIndex)
    )

    finalB = fold64(
        "SHEP58A|KEY|STREAM|FINAL|B|"
        + headDigest + "|"
        + state + "|"
        + str(directBits) + "|"
        + str(laneBits) + "|"
        + str(blockBytes)
    )

    return computeBound(
        finalA
        + finalB
        + leftPad(totalLen, 15)
        + leftPad(laneIndex, 8)
    )[0].lower()

def computeKeyDigestFile(path, directBits=256, laneBits=336, blockBytes=65536):
    directBytes = max(1, (int(directBits) + 7) // 8)
    laneBytes = max(directBytes + 1, (int(laneBits) + 7) // 8)
    blockBytes = max(laneBytes, int(blockBytes))
    totalLen = os.path.getsize(path)

    with open(path, "rb") as fp:
        if totalLen <= directBytes:
            raw = fp.read()
            return computeKeyDigest(encodeSentinel(raw))[0].lower()

        head = fp.read(directBytes)
        headDigest = computeKeyDigest(encodeSentinel(head))[0].lower()

        state = computeBound(
            fold64(
                "SHEP58A|KEY|STREAM|ROOT|"
                + str(directBits) + "|"
                + str(laneBits) + "|"
                + str(totalLen) + "|"
                + headDigest
            )
        )[0].lower()

        fp.seek(0)
        laneIndex = 0
        blockOff = 0

        while True:
            block = fp.read(blockBytes)
            if not block:
                break

            blockState = fold64(
                "SHEP58A|KEY|STREAM|BLOCK|"
                + state + "|"
                + str(blockOff) + "|"
                + str(len(block)) + "|"
                + str(totalLen)
            )

            for innerOff in range(0, len(block), laneBytes):
                lane = block[innerOff:innerOff + laneBytes]
                laneHex = encodeHex(encodeSentinel(lane))

                frameA = fold64(
                    "SHEP58A|KEY|STREAM|LEAF|A|"
                    + blockState + "|"
                    + str(laneIndex) + "|"
                    + str(len(lane)) + "|"
                    + laneHex
                )

                frameB = fold64(
                    "SHEP58A|KEY|STREAM|LEAF|B|"
                    + state + "|"
                    + headDigest + "|"
                    + str(totalLen) + "|"
                    + str(laneIndex)
                )

                blockState = computeBound(
                    frameA
                    + frameB
                    + leftPad(laneIndex, 8)
                    + leftPad(len(lane), 5)
                    + leftPad(totalLen, 15)
                )[0].lower()

                laneIndex += 1

            state = computeBound(
                fold64(
                    "SHEP58A|KEY|STREAM|BLOCK|FINAL|"
                    + state + "|"
                    + blockState + "|"
                    + str(blockOff) + "|"
                    + str(len(block)) + "|"
                    + str(laneIndex)
                )
            )[0].lower()

            blockOff += len(block)

    finalA = fold64(
        "SHEP58A|KEY|STREAM|FINAL|A|"
        + state + "|"
        + headDigest + "|"
        + str(totalLen) + "|"
        + str(laneIndex)
    )

    finalB = fold64(
        "SHEP58A|KEY|STREAM|FINAL|B|"
        + headDigest + "|"
        + state + "|"
        + str(directBits) + "|"
        + str(laneBits) + "|"
        + str(blockBytes)
    )

    return computeBound(
        finalA
        + finalB
        + leftPad(totalLen, 15)
        + leftPad(laneIndex, 8)
    )[0].lower()

def bindState(trace, modeId="32"):
    parts = [
        str(modeId),
        truncatePrefix(trace["input"], 24),
        truncatePrefix(trace["first"], 96),
        truncatePrefix(trace["firstPad"], 96),
        truncatePrefix(trace["second"], 96),
        truncatePrefix(trace["third"], 96),
        truncatePrefix(trace["fourth"], 96),
        truncatePrefix(trace["left"], 96),
        truncatePrefix(trace["mix"], 96),
        truncatePrefix(trace["right"], 96),
        truncatePrefix(trace["value"], 96),
    ]
    a = fold64("|".join(parts))
    b = computeBound(a)[0].lower()
    c = processKey(decodeShift(b, 16))
    d = fold64(a + b + c + truncatePrefix(trace["packedLen"], 8))
    e = computeBound(d + a)[0].lower()
    return fold64(e + d + b + a)

def computeHex(trace, modeId="333", seedHex=None):
    root = seedHex if seedHex else bindState(trace, modeId + "|BASE")
    a = fold64(root + truncatePrefix(trace["value"], 128))
    b = computeBound(a)[0].lower()
    c = fold64(b + root + truncatePrefix(trace["mix"], 128))
    d = computeBound(c + a)[0].lower()
    return (c + d)[:64]

def scheduleText(sched):
    out = []
    for pos, ch, val in sched:
        out.append(leftPad(pos, 2))
        out.append(ch)
        out.append(leftPad(val, 2))
    return "".join(out)

def deriveInjection(trace, baseHexStr, count=8, modeId="333", seedHex=None):
    if not isinstance(count, int) or count < 1 or count > 8:
        raise ValueError("count must be in 1..8")
    totalLen = 64 + count
    aux = deriveAuxCharset()
    avail = list(range(totalLen))
    state = seedHex if seedHex else bindState(trace, modeId + "|LOTTERY")
    sched = []
    for i in range(count):
        posSeed = fold64("POS|" + str(i) + "|" + state + "|" + truncatePrefix(trace["left"], 96) + "|" + baseHexStr)
        valSeed = fold64("VAL|" + str(i) + "|" + state + "|" + truncatePrefix(trace["right"], 96) + "|" + baseHexStr)
        pick = decodeShift(posSeed, 16) % len(avail)
        pos = avail.pop(pick)
        val = decodeShift(valSeed, 16) % len(aux)
        ch = aux[val]
        sched.append((pos, ch, val))
        state = fold64("ROUND|" + str(i) + "|" + state + "|" + str(pos) + "|" + str(val) + "|" + truncatePrefix(trace["mix"], 96) + "|" + baseHexStr)
    return sched

def distributeSymbols(baseHexStr, sched, count=8):
    totalLen = 64 + count
    out = [""] * totalLen
    for pos, ch, _ in sched:
        out[pos] = ch
    j = 0
    for i in range(totalLen):
        if out[i] == "":
            out[i] = baseHexStr[j]
            j += 1
    return "".join(out)

def computeTraceDigest(trace):
    root = bindState(trace, "32|FINAL")
    a = fold64(root + truncatePrefix(trace["value"], 128))
    b = computeBound(a)[0].lower()
    c = fold64(b + root + truncatePrefix(trace["right"], 128))
    return c[:64]

def computeTraceExtended(trace, count=8):
    root = bindState(trace, "333|ROOT")
    bodyB = computeHex(trace, "333|BASE", root)
    pepperB = deriveInjection(trace, bodyB, count, "333|LOTTERY", root)
    raw = distributeSymbols(bodyB, pepperB, count)
    rebound = fold64(root + raw + scheduleText(pepperB) + truncatePrefix(trace["first"], 96))
    body = computeHex(trace, "333|BASE2", rebound)
    pepper = deriveInjection(trace, body, count, "333|LOTTERY2", rebound)
    return distributeSymbols(body, pepper, count)

def generatePrimaryKey(x=None, directBits=256, laneBits=336, blockBytes=4096):
    source = generateSeedSource() if x is None else x
    raw = normalizeSeedBytes(source)
    return computeKeyDigestStream(raw, directBits, laneBits, blockBytes)

def generateExtendedKey(x=None, count=8, directBits=256, laneBits=336, blockBytes=4096):
    source = generateSeedSource() if x is None else x
    raw = normalizeSeedBytes(source)

    directBytes = max(1, (int(directBits) + 7) // 8)
    if len(raw) <= directBytes:
        trace = traceWideState(encodeSentinel(raw))
        return computeTraceExtended(trace, count)

    streamRoot = computeKeyDigestStream(raw, directBits, laneBits, blockBytes)
    trace = traceWideState(encodeTextBlock(streamRoot))
    return computeTraceExtended(trace, count)

def generateKey(x=None, mode=0, count=8, directBits=256, laneBits=336, blockBytes=4096):
    return generatePrimaryKey(x, directBits, laneBits, blockBytes) if int(mode) == 0 else generateExtendedKey(x, count, directBits, laneBits, blockBytes)

def generateKeyFile(path, mode=0, count=8, directBits=256, laneBits=336, blockBytes=65536):
    root = computeKeyDigestFile(path, directBits, laneBits, blockBytes)
    return root if int(mode) == 0 else computeTraceExtended(traceWideState(encodeTextBlock(root)), count)

# =========================
# Encryption and decryption
# Build Version: 58C
# NOTES: Deterministic key normalization, one-string randomized envelope, strict authentication, and chunked encryption/decryption.
# =========================

def verifyEqual(a, b):
    a = "" if a is None else str(a)
    b = "" if b is None else str(b)
    x = len(a) ^ len(b)
    m = max(len(a), len(b))
    for i in range(m):
        ca = ord(a[i]) if i < len(a) else 0
        cb = ord(b[i]) if i < len(b) else 0
        x |= ca ^ cb
    return x == 0

def deriveMessageKeys(masterHex, saltHex, nonceHex, ivHex):
    leftSeed = fold64(masterHex + saltHex + nonceHex + ivHex)
    rightSeed = fold64(ivHex + nonceHex + saltHex + masterHex)
    encRoot = computeBound(leftSeed + rightSeed)[0].lower()
    authRoot = computeBound(rightSeed + leftSeed)[0].lower()
    return encRoot, authRoot

def deriveBlockKey(encRoot, chunkIndex, saltHex, nonceHex, ivHex):
    counterHex = encodeHex(int(chunkIndex)).zfill(16)[-16:]
    roundSeed = fold64(encRoot + saltHex + nonceHex + ivHex + counterHex)
    return computeBound(roundSeed + encRoot + counterHex)[0].lower()

def computeAuthTag(authRoot, meta, sep, body):
    lens = meta["lens"]
    header = "|".join([
        str(meta["ver"]),
        str(meta["mode"]),
        str(meta["suite"]),
        str(meta["kdfId"]),
        str(meta["macId"]),
        str(meta["flags"]),
        str(meta["chunkSize"]),
        str(meta["origLen"]),
        str(meta["compLen"]),
        str(len(lens)),
        ",".join(str(x) for x in lens),
        str(meta["msgSeedDec"]),
        str(sep),
    ])
    chain = computeBound(fold64(authRoot + header))[0].lower()
    stride = 256
    blockIndex = 0
    for off in range(0, len(body), stride):
        block = body[off:off + stride]
        blockHex = encodeHex(encodeTextBlock(block))
        idxHex = encodeHex(blockIndex).zfill(8)
        lenHex = encodeHex(len(block)).zfill(8)
        chain = computeBound(fold64(chain + authRoot + idxHex + lenHex + blockHex))[0].lower()
        blockIndex += 1
    return computeBound(fold64(chain + authRoot + encodeHex(blockIndex).zfill(8)))[0].lower()

def executeForward(n, keys, b):
    for key in keys:
        n = partitionKey(n, key, 1)
        n = decodeShift(str(diffuseSequence(str(n), key)), 10)
        n = distributeRadix(int(n), key, b, 1)
        n = diffuseBits(n, str(key))
        if int(str(key)[0]) % 2 == 1:
            n = int(interleaveStreams(str(n)))
    return n

def executeInverse(n, keys, b):
    for key in reversed(keys):
        if int(str(key)[0]) % 2 == 1:
            n = int(separateStreams(str(n)))
        n = diffuseBits(n, str(key))
        n = encodeShift(distributeRadix(int(n), key, b, 0), 10)
        n = recoverSequence(n, key)
        n = partitionKey(int(n), key, 0)
    return n

def encryptBlock(nInt, hKey):
    e = deriveBaseFactor(hKey)
    key0 = decodeShift(hKey, 16)
    b = e
    keys = [key0]
    key = key0
    for _ in range(9):
        key = int(processKey(key))
        keys.append(key)
    nInt = nInt + (key // b)
    nInt = executeForward(nInt, keys, b)
    return encodeShift(nInt, 62)

def decryptBlock(cText, hKey):
    e = deriveBaseFactor(hKey)
    key0 = decodeShift(hKey, 16)
    b = e
    nInt = decodeShift(cText, 62)
    keys = [key0]
    key = key0
    for _ in range(9):
        key = int(processKey(key))
        keys.append(key)
    nInt = executeInverse(nInt, keys, b)
    nInt = nInt - (key // b)
    return nInt

def isExtendedKey(k, count=8):
    if not isinstance(k, str):
        return False
    if len(k) != 64 + int(count):
        return False
    valid = set(gCharBase)
    return all(ch in valid for ch in k)

def resolveKey(k, allowAuto=False, keyMode=0, count=8):
    keyMode = int(keyMode)

    if k is None or k == 0 or (isinstance(k, str) and not k.strip()):
        if not allowAuto:
            raise ValueError("key/passphrase required")
        return generateKey(None, keyMode, count), 0

    if keyMode == 0:
        if isinstance(k, str) and isHex64(k.strip()):
            return k.strip().lower(), 0
        return generatePrimaryKey(k), 1

    if isinstance(k, str):
        s = k.strip()
        if isExtendedKey(s, count):
            return s, 0
    return generateExtendedKey(k, count), 1

def encryptData(n, k=None, keyMode=0, count=8):
    if not isinstance(n, str):
        raise ValueError("encryptData expects a string")

    keyMode = int(keyMode)
    modeMarker = 0 if keyMode == 0 else 333

    hKey, kdfId = resolveKey(k, True, keyMode, count)
    msgSeedDec = deriveWrapSeed()
    saltHex, nonceHex, ivHex = expandSeedState(msgSeedDec)
    encRoot, authRoot = deriveMessageKeys(hKey, saltHex, nonceHex, ivHex)

    rawBytes = n.encode("utf-16-le", errors="surrogatepass")
    compBytes = zlib.compress(rawBytes, 9)
    parts = splitByteBlocks(compBytes, 2048)

    totalSteps = len(parts) + 3
    done = 0
    cipherParts = []
    lens = []

    for idx, p in enumerate(parts):
        done += 1
        _printProg("ENC", done, totalSteps)
        chunkKey = deriveBlockKey(encRoot, idx, saltHex, nonceHex, ivHex)
        cPart = encryptBlock(encodeSentinel(p), chunkKey)
        cipherParts.append(cPart)
        lens.append(len(cPart))

    joinedCipher = "".join(cipherParts)
    obfBody = obfuscateProgress(joinedCipher, hKey, 64, "ENC", done, totalSteps)
    sep = deriveSecureSeparator()

    meta = {
        "ver": 1,
        "mode": modeMarker,
        "suite": 1,
        "kdfId": kdfId,
        "macId": 0,
        "flags": 3,
        "chunkSize": 2048,
        "origLen": len(rawBytes),
        "compLen": len(compBytes),
        "lens": lens,
        "msgSeedDec": msgSeedDec,
    }

    tagHex = computeAuthTag(authRoot, meta, sep, obfBody)
    tail = loadTail(
        meta["ver"],
        meta["mode"],
        meta["suite"],
        meta["kdfId"],
        meta["macId"],
        meta["flags"],
        meta["chunkSize"],
        meta["origLen"],
        meta["compLen"],
        lens,
        msgSeedDec,
        tagHex
    )
    return obfBody + sep + tail, hKey

def decryptData(n, k, keyMode=None, count=8):
    if not isinstance(n, str):
        raise ValueError("decryptData expects a string ciphertext")

    obfBody, sep, tail = pruneTail(n)
    meta = parseTail(tail)

    modeValue = meta["mode"] if keyMode is None else int(keyMode)
    resolvedMode = 0 if int(modeValue) == 0 else 333
    hKey, _ = resolveKey(k, False, resolvedMode, count)

    saltHex, nonceHex, ivHex = expandSeedState(meta["msgSeedDec"])
    encRoot, authRoot = deriveMessageKeys(hKey, saltHex, nonceHex, ivHex)

    expectTag = computeAuthTag(authRoot, meta, sep, obfBody)
    if not verifyEqual(expectTag, meta["tagHex"]):
        raise ValueError("wrong key or damaged ciphertext")

    totalSteps = len(meta["lens"]) + 3
    if totalSteps < 4:
        totalSteps = 4

    done = 0
    body = deobfuscateProgress(obfBody, hKey, 64, "DEC", done, totalSteps)
    done += 3

    compOut = bytearray()
    pos = 0
    for idx, L in enumerate(meta["lens"]):
        done += 1
        _printProg("DEC", done, totalSteps)
        cPart = body[pos:pos + L]
        pos += L
        chunkKey = deriveBlockKey(encRoot, idx, saltHex, nonceHex, ivHex)
        pInt = decryptBlock(cPart, chunkKey)
        compOut.extend(decodeSentinel(pInt))

    if pos != len(body):
        raise ValueError("wrong key or damaged ciphertext")

    rawBytes = bytes(compOut)
    if meta["compLen"] > 0:
        rawBytes = rawBytes[:meta["compLen"]]
    if not verifyZlib(rawBytes):
        raise ValueError("wrong key or damaged ciphertext")
    rawBytes = zlib.decompress(rawBytes)
    if meta["origLen"] > 0:
        rawBytes = rawBytes[:meta["origLen"]]
    return decodeSafeText(rawBytes)

generateKey("")