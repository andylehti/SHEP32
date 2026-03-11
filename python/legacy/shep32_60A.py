
# =========================
# Main imports and runtime
# Build Version: 60A
# NOTES: Standard-library dependencies required for transforms, progress output, compression, and deterministic RNG support.
# =========================

import math, os, sys, time, zlib, tempfile, traceback, json, hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# =========================
# Core constants and general helpers
# Build Version: 60A
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
# Build Version: 60A
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
# Build Version: 60A
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
# Build Version: 60A
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
# Build Version: 60A
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
# Build Version: 60A
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

def diffuseBlocks(data, v=0, cols=73, rows=72):
    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        raw = bytes(data)

    cols = int(cols)
    rows = int(rows)
    if cols < 1 or rows < 1:
        raise ValueError("cols and rows must be >= 1")

    mask = 0xFFFFFFFFFFFFFFFF
    laneCount = cols
    blockBytes = max(1, ((cols * rows) + 7) // 8)
    outLen = cols * 5

    def rot(x, r):
        x &= mask
        r &= 63
        if r == 0:
            return x
        return ((x << r) | (x >> (64 - r))) & mask

    def mix64(x):
        x &= mask
        x ^= x >> 30
        x = (x * 0xBF58476D1CE4E5B9) & mask
        x ^= x >> 27
        x = (x * 0x94D049BB133111EB) & mask
        x ^= x >> 31
        return x & mask

    def h64(x):
        y = fold64(x)
        if isinstance(y, (tuple, list)):
            y = y[0]
        return int(str(y), 16) & mask

    def word64(b, i):
        return int.from_bytes(b[i:i + 8], "little")

    def runPass(src, seedA, seedB):
        src = bytes(src)
        state = [0] * laneCount
        for i in range(laneCount):
            state[i] = mix64(seedA ^ (((i + 1) * 0x9E3779B185EBCA87) & mask) ^ rot(seedB, (i % 31) + 1) ^ ((len(src) + i) * 0xD6E8FEB86659FD93))

        blocks = []
        blockIndex = 0
        for off in range(0, len(src), blockBytes):
            block = src[off:off + blockBytes]
            blockLen = len(block)
            blockState = mix64(seedB ^ blockIndex ^ blockLen ^ rot(state[blockIndex % laneCount], ((blockIndex % 29) + 1)))
            wordCount = (blockLen + 7) // 8

            for wIndex in range(wordCount):
                pos = wIndex * 8
                word = word64(block, pos)
                g = off + pos

                i = (word + g + blockIndex) % laneCount
                j = (i + 17 + (wIndex % 13)) % laneCount
                k = (i * 7 + 29 + (word >> 11)) % laneCount

                a = state[i]
                b = state[j]
                c = state[k]

                x = mix64(word ^ blockState ^ ((g + 1) * 0x9E3779B185EBCA87) ^ len(src))
                state[i] = mix64((a + x + rot(b, 13) + rot(c, 29)) & mask)
                state[j] = mix64(b ^ x ^ rot(a, 17) ^ rot(c, 37))
                state[k] = mix64((c + x + rot(b, 43) + rot(a, 53) + wordCount + wIndex) & mask)

                blockState = mix64(blockState ^ x ^ state[i] ^ rot(state[j], 11) ^ rot(state[k], 23))

                if (wIndex & 7) == 7:
                    t = (i + j + k + wIndex) % laneCount
                    u = (t + 31) % laneCount
                    state[t] = mix64(state[t] ^ blockState ^ rot(state[u], 19) ^ ((g + 1) * 0xD6E8FEB86659FD93))
                    state[u] = mix64((state[u] + state[t] + rot(blockState, 27) + x) & mask)

            p = blockIndex % laneCount
            q = (p + 23) % laneCount
            r = (p + 47) % laneCount
            d = mix64(blockState ^ blockLen ^ off ^ len(src))
            state[p] = mix64(state[p] ^ d ^ rot(blockState, 17))
            state[q] = mix64((state[q] + d + rot(state[p], 9) + len(src) + blockIndex) & mask)
            state[r] = mix64(state[r] ^ rot(d, 33) ^ state[p] ^ state[q] ^ blockLen)

            blocks.append({"i": blockIndex, "n": blockLen, "s": blockState, "d": d})
            blockIndex += 1

        rounds = max(6, rows // 12)
        for rnd in range(rounds):
            seed = mix64(seedA ^ seedB ^ rnd ^ len(src) ^ state[rnd % laneCount])
            prev = state[-1]
            for i in range(laneCount):
                cur = state[i]
                nxt = state[(i + 1) % laneCount]
                far = state[(i * 7 + rnd + 3) % laneCount]
                m = mix64(cur ^ rot(nxt, ((i + rnd) % 31) + 1) ^ rot(far, ((i * 3 + rnd) % 31) + 1) ^ prev ^ seed ^ i ^ len(src))
                state[i] = mix64((cur + m + rot(prev, 13) + rot(seed, 1 + ((i + rnd) % 31))) & mask)
                prev = cur
            pivot = rnd % laneCount
            state[pivot] = mix64(state[pivot] ^ seed ^ rot(state[(pivot + 19) % laneCount], 7))
            state[(pivot + 37) % laneCount] = mix64((state[(pivot + 37) % laneCount] + rot(seed, 23) + state[pivot]) & mask)

        out = bytearray(outLen)
        seed = mix64(seedA ^ seedB ^ len(src) ^ len(blocks))
        pos = 0
        for phase in range(5):
            for i in range(laneCount):
                a = state[i]
                b = state[(i + phase + 1) % laneCount]
                c = state[(i * 11 + phase + 7) % laneCount]
                q = mix64(a ^ rot(b, ((phase + i) % 31) + 1) ^ rot(c, ((phase * 7 + i) % 31) + 1) ^ seed ^ (phase << 8) ^ i)
                out[pos] = q & 0xFF
                pos += 1
                state[i] = mix64((a + q + rot(c, 17) + rot(seed, 1 + (i % 31))) & mask)
            seed = mix64(seed ^ state[phase % laneCount] ^ rot(state[(phase * 11 + 3) % laneCount], 19))

        return blocks, out

    totalLen = len(raw)
    head = raw[:128]
    seedA = mix64(totalLen ^ cols ^ (rows << 32) ^ 0x243F6A8885A308D3)
    seedB = h64(raw[:256].hex() + "|" + raw[-256:].hex() + "|" + str(totalLen)) if raw else mix64(seedA ^ 0x13198A2E03707344)

    blocksA, arrA = runPass(raw, seedA, seedB)
    mixIn = bytes(arrA) + head
    seedC = mix64(seedB ^ h64(head.hex() + "|" + bytes(arrA[:64]).hex() + "|" + str(len(mixIn))))
    blocksB, arrB = runPass(mixIn, seedB, seedC)

    merged = bytearray(outLen)
    mergeSeed = mix64(seedA ^ seedB ^ seedC ^ len(mixIn) ^ outLen)
    headLen = len(head)

    for i in range(outLen):
        a = arrA[i]
        b = arrB[i]
        c = head[i % headLen] if headLen else ((i * 17 + totalLen) & 0xFF)
        m = mix64(mergeSeed ^ a ^ (b << 8) ^ (c << 16) ^ (i << 24))
        merged[i] = (a ^ b ^ c ^ m ^ (m >> 8) ^ (m >> 16) ^ (m >> 24)) & 0xFF
        mergeSeed = mix64(mergeSeed ^ m ^ a ^ (b << 8) ^ (c << 16) ^ i)

    globalSum = h64(merged.hex() + "|" + str(totalLen) + "|" + str(len(blocksA)) + "|" + str(len(blocksB)))

    if v == 1:
        return bytes(merged)

    return {"blocksA": blocksA, "blocksB": blocksB, "final": list(merged), "globalSum": globalSum}

def computeKeyDigestStream(b, directBits=256, laneBits=336, blockBytes=4096):
    raw = bytes(b)
    directBytes = max(1, (int(directBits) + 7) // 8)

    if len(raw) <= directBytes:
        return computeKeyDigest(encodeSentinel(raw))[0].lower()

    diffused = diffuseBlocks(raw, 1)
    routeSeed = encodeSentinel(diffused)
    return computeKeyDigest(routeSeed)[0].lower()

def computeKeyDigestFile(path, directBits=256, laneBits=336, blockBytes=65536):
    directBytes = max(1, (int(directBits) + 7) // 8)
    with open(path, "rb") as fp:
        raw = fp.read()

    if len(raw) <= directBytes:
        return computeKeyDigest(encodeSentinel(raw))[0].lower()

    diffused = diffuseBlocks(raw, 1)
    routeSeed = encodeSentinel(diffused)
    return computeKeyDigest(routeSeed)[0].lower()

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

    diffused = diffuseBlocks(raw, 1)
    trace = traceWideState(encodeSentinel(diffused))
    return computeTraceExtended(trace, count)

def generateKey(x=None, mode=0, count=8, directBits=256, laneBits=336, blockBytes=4096):
    return generatePrimaryKey(x, directBits, laneBits, blockBytes) if int(mode) == 0 else generateExtendedKey(x, count, directBits, laneBits, blockBytes)

def generateKeyFile(path, mode=0, count=8, directBits=256, laneBits=336, blockBytes=65536):
    directBytes = max(1, (int(directBits) + 7) // 8)
    with open(path, "rb") as fp:
        raw = fp.read()

    if int(mode) == 0:
        return computeKeyDigestStream(raw, directBits, laneBits, blockBytes)

    if len(raw) <= directBytes:
        return computeTraceExtended(traceWideState(encodeSentinel(raw)), count)

    diffused = diffuseBlocks(raw, 1)
    return computeTraceExtended(traceWideState(encodeSentinel(diffused)), count)

# =========================
# Encryption and decryption
# Build Version: 60A
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

def packPortableBytes(b):
    return encodeShift(encodeSentinel(bytes(b)), 62)

def unpackPortableBytes(s):
    return decodeSentinel(decodeShift(str(s), 62))

def canonicalJson(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def parseJson(s):
    return json.loads(str(s))

def buildMetaCore(meta):
    return canonicalJson(meta)

def leadingZeroBits(digest):
    n = 0
    for b in bytes(digest):
        if b == 0:
            n += 8
        else:
            return n + (8 - b.bit_length())
    return n

def buildPowHeader(meta, bodyPacked):
    core = {k: v for k, v in meta.items() if k not in {"powNonce", "powHash"}}
    bodyHash = hashlib.sha256(str(bodyPacked).encode("ascii")).hexdigest()
    return (buildMetaCore(core) + "|" + bodyHash).encode("utf-8")

def solvePow(meta, bodyPacked, bits=0, startNonce=0):
    bits = int(bits)
    if bits <= 0:
        return 0, ""
    prefix = buildPowHeader(meta, bodyPacked)
    nonce = int(startNonce)
    while True:
        nbytes = nonce.to_bytes(16, "big")
        digest = hashlib.sha256(prefix + nbytes).digest()
        if leadingZeroBits(digest) >= bits:
            return nonce, digest.hex()
        nonce += 1

def verifyPow(meta, bodyPacked):
    bits = int(meta.get("powBits", 0))
    if bits <= 0:
        return True
    nonce = int(meta.get("powNonce", 0))
    expect = str(meta.get("powHash", "")).lower()
    prefix = buildPowHeader(meta, bodyPacked)
    digest = hashlib.sha256(prefix + nonce.to_bytes(16, "big")).digest()
    return verifyEqual(expect, digest.hex()) and leadingZeroBits(digest) >= bits

def xrotl32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def xquarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = xrotl32(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = xrotl32(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = xrotl32(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = xrotl32(state[b], 7)

def hChaCha20(key32, nonce16):
    if len(key32) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce16) != 16:
        raise ValueError("nonce must be 16 bytes")
    const = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    keyWords = [int.from_bytes(key32[i:i+4], "little") for i in range(0, 32, 4)]
    nonceWords = [int.from_bytes(nonce16[i:i+4], "little") for i in range(0, 16, 4)]
    state = const + keyWords + nonceWords
    work = state[:]
    for _ in range(10):
        xquarter(work, 0, 4, 8, 12)
        xquarter(work, 1, 5, 9, 13)
        xquarter(work, 2, 6, 10, 14)
        xquarter(work, 3, 7, 11, 15)
        xquarter(work, 0, 5, 10, 15)
        xquarter(work, 1, 6, 11, 12)
        xquarter(work, 2, 7, 8, 13)
        xquarter(work, 3, 4, 9, 14)
    outWords = [work[0], work[1], work[2], work[3], work[12], work[13], work[14], work[15]]
    return b"".join(x.to_bytes(4, "little") for x in outWords)

def xChaCha20Poly1305Encrypt(key32, nonce24, data, aad=b""):
    if len(key32) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce24) != 24:
        raise ValueError("nonce must be 24 bytes")
    subkey = hChaCha20(key32, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    return ChaCha20Poly1305(subkey).encrypt(nonce12, bytes(data), bytes(aad))

def xChaCha20Poly1305Decrypt(key32, nonce24, data, aad=b""):
    if len(key32) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce24) != 24:
        raise ValueError("nonce must be 24 bytes")
    subkey = hChaCha20(key32, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    return ChaCha20Poly1305(subkey).decrypt(nonce12, bytes(data), bytes(aad))

def isExtendedKey(k, count=8):
    if not isinstance(k, str):
        return False
    if len(k) != 64 + int(count):
        return False
    valid = set(gCharBase)
    if not all(ch in valid for ch in k):
        return False
    return sum(ch in gAuxBase for ch in k) == int(count)

def unpackExtendedKey(k, count=8):
    if not isExtendedKey(k, count):
        raise ValueError("invalid extended key")
    body = []
    sched = []
    segments = []
    cur = []
    for pos, ch in enumerate(k):
        if ch in gAuxBase:
            segments.append("".join(cur))
            cur = []
            sched.append((pos, ch, gAuxBase.index(ch)))
        else:
            cur.append(ch)
            body.append(ch)
    segments.append("".join(cur))
    bodyHex = "".join(body).lower()
    if not isHex64(bodyHex) or len(sched) != int(count):
        raise ValueError("invalid extended key structure")
    schedText = scheduleText(sched)
    mixHex = computeBound(fold64("EXT|ROOT|" + bodyHex + "|" + schedText + "|" + str(count)) + bodyHex)[0].lower()
    return {"bodyHex": bodyHex, "sched": sched, "schedText": schedText, "mixHex": mixHex, "segments": segments}

def remixExtendedKey(k, count=8):
    ext = unpackExtendedKey(k, count)
    segments = ext["segments"]
    sched = ext["sched"]
    peppers = [ch for _, ch, _ in sched]
    vals = [val for _, _, val in sched]
    avail = list(range(len(segments)))
    order = []
    state = sum((i + 1) * (v + 1) for i, v in enumerate(vals)) + len(ext["bodyHex"]) + int(count)
    for i, v in enumerate(vals):
        pick = (state + v + i + (v * (i + 3))) % len(avail)
        order.append(avail.pop(pick))
        state = diffuseWord64(state ^ ((v + 1) << ((i * 7) % 29)))
    order.extend(avail)
    remixedSegments = [segments[i] for i in order]
    out = []
    for i in range(len(peppers)):
        out.append(remixedSegments[i])
        out.append(peppers[i])
    out.append(remixedSegments[-1])
    return "".join(out), order

def computeKeyPair(masterKey, keyMode=0, count=8):
    keyMode = 0 if int(keyMode) == 0 else 333
    if keyMode != 0 and isinstance(masterKey, str) and isExtendedKey(masterKey, count):
        ext = unpackExtendedKey(masterKey, count)
        remix, order = remixExtendedKey(masterKey, count)
        key1 = ext["bodyHex"].lower()
        key2 = generatePrimaryKey(masterKey + remix).lower()
        return {
            "key1": key1,
            "key2": key2,
            "schedText": ext["schedText"],
            "mixHex": ext["mixHex"],
            "remix": remix,
            "order": order,
        }
    base = str(masterKey).strip().lower()
    if not isHex64(base):
        base = generatePrimaryKey(masterKey).lower()
    key1 = base
    key2 = generatePrimaryKey("PAIR|" + key1).lower()
    return {"key1": key1, "key2": key2, "schedText": "", "mixHex": "", "remix": "", "order": []}

def deriveInternalKey(masterKey, keyMode=0, count=8, label="ROOT"):
    pair = computeKeyPair(masterKey, keyMode, count)
    seed = fold64(
        "KEY|" + str(label) + "|" + pair["key1"] + "|" + pair["key2"] + "|"
        + pair["schedText"] + "|" + pair["mixHex"] + "|" + pair["remix"] + "|"
        + str(0 if int(keyMode) == 0 else 333) + "|" + str(int(count))
    )
    return computeBound(seed + pair["key1"] + pair["key2"])[0].lower()

def deriveObfKey(masterKey, keyMode=0, count=8):
    return deriveInternalKey(masterKey, keyMode, count, "OBF")

def resolveKey(k, allowAuto=False, keyMode=0, count=8):
    keyMode = int(keyMode)
    if k is None:
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

def deriveMessageKeys(masterKey, saltHex, nonceHex, ivHex, keyMode=0, count=8):
    encBase = deriveInternalKey(masterKey, keyMode, count, "ENC")
    authBase = deriveInternalKey(masterKey, keyMode, count, "AUTH")
    nonceBase = deriveInternalKey(masterKey, keyMode, count, "NONCE")
    verifyBase = deriveInternalKey(masterKey, keyMode, count, "VERIFY")
    pubBase = deriveInternalKey(masterKey, keyMode, count, "PUBSEED")
    encRoot = computeBound(fold64(encBase + saltHex + nonceHex + ivHex) + encBase)[0].lower()
    authRoot = computeBound(fold64(authBase + ivHex + saltHex + nonceHex) + authBase)[0].lower()
    nonceRoot = computeBound(fold64(nonceBase + nonceHex + ivHex + saltHex) + nonceBase)[0].lower()
    verifyRoot = computeBound(fold64(verifyBase + saltHex + ivHex + nonceHex) + verifyBase)[0].lower()
    pubRoot = computeBound(fold64(pubBase + saltHex + nonceHex + ivHex) + pubBase)[0].lower()
    return {"encRoot": encRoot, "authRoot": authRoot, "nonceRoot": nonceRoot, "verifyRoot": verifyRoot, "pubRoot": pubRoot}

def deriveBlockKey(encRoot, chunkIndex, saltHex, nonceHex, ivHex):
    idxHex = encodeHex(int(chunkIndex)).zfill(16)[-16:]
    return computeBound(fold64(encRoot + saltHex + nonceHex + ivHex + idxHex) + encRoot + idxHex)[0].lower()

def deriveChunkNonce(nonceRoot, chunkIndex, saltHex, nonceHex, ivHex):
    idxHex = encodeHex(int(chunkIndex)).zfill(16)[-16:]
    a = computeBound(fold64(nonceRoot + saltHex + idxHex + nonceHex) + nonceRoot)[0].lower()
    b = computeBound(fold64(ivHex + idxHex + nonceRoot + saltHex) + nonceHex)[0].lower()
    return bytes.fromhex((a + b)[:48])

def buildChunkAad(meta, idx):
    core = {
        "ver": meta["ver"],
        "alg": meta["alg"],
        "mode": meta["mode"],
        "suite": meta["suite"],
        "kdfId": meta["kdfId"],
        "chunkSize": meta["chunkSize"],
        "origLen": meta["origLen"],
        "compLen": meta["compLen"],
        "msgSeedDec": meta["msgSeedDec"],
        "idx": int(idx),
    }
    return buildMetaCore(core).encode("utf-8")

def computeVerifyToken(verifyRoot, meta):
    core = {k: v for k, v in meta.items() if k not in {"verify", "authTag", "powNonce", "powHash"}}
    return computeBound(fold64("VERIFY|" + verifyRoot + "|" + buildMetaCore(core)) + verifyRoot)[0].lower()[:32]

def computeAuthTag(authRoot, meta, bodyPacked, detached=0):
    core = {k: v for k, v in meta.items() if k not in {"authTag", "powNonce", "powHash"}}
    chain = computeBound(fold64("AUTH|" + authRoot + "|" + buildMetaCore(core) + "|" + str(int(detached))) + authRoot)[0].lower()
    stride = 256
    idx = 0
    for off in range(0, len(bodyPacked), stride):
        block = bodyPacked[off:off + stride]
        chain = computeBound(fold64(chain + authRoot + encodeHex(idx).zfill(8) + block) + authRoot)[0].lower()
        idx += 1
    return computeBound(fold64(chain + authRoot + encodeHex(idx).zfill(8)) + authRoot)[0].lower()

def encodeEnvelope(meta, bodyPacked):
    headerBytes = buildMetaCore(meta).encode("utf-8")
    n = len(headerBytes).to_bytes(4, "big")
    return packPortableBytes(n + headerBytes + str(bodyPacked).encode("ascii"))

def decodeEnvelope(token):
    payload = unpackPortableBytes(token)
    if len(payload) < 4:
        raise ValueError("invalid ciphertext envelope")
    n = int.from_bytes(payload[:4], "big")
    if len(payload) < 4 + n:
        raise ValueError("invalid ciphertext envelope")
    headerBytes = payload[4:4 + n]
    bodyPacked = payload[4 + n:].decode("ascii")
    return parseJson(headerBytes.decode("utf-8")), bodyPacked

def encryptData(n, k=None, keyMode=0, count=8, detached=False, compress=True, chunkSize=2048, powBits=0, powStart=0, saltHex=None, nonceHex=None, ivHex=None):
    if not isinstance(n, str):
        raise ValueError("encryptData expects a string")

    keyMode = int(keyMode)
    modeMarker = 0 if keyMode == 0 else 333
    hKey, kdfId = resolveKey(k, True, keyMode, count)

    msgSeedDec = deriveWrapSeed()
    ds, dn, di = expandSeedState(msgSeedDec)
    saltHex = str(saltHex).lower() if saltHex else ds
    nonceHex = str(nonceHex).lower() if nonceHex else dn
    ivHex = str(ivHex).lower() if ivHex else di

    msgKeys = deriveMessageKeys(hKey, saltHex, nonceHex, ivHex, keyMode, count)

    rawBytes = n.encode("utf-16-le", errors="surrogatepass")
    compBytes = zlib.compress(rawBytes, 9) if compress else rawBytes
    parts = splitByteBlocks(compBytes, int(chunkSize))

    cipherParts = []
    lens = []
    for idx, p in enumerate(parts):
        chunkKey = bytes.fromhex(deriveBlockKey(msgKeys["encRoot"], idx, saltHex, nonceHex, ivHex))
        chunkNonce = deriveChunkNonce(msgKeys["nonceRoot"], idx, saltHex, nonceHex, ivHex)
        metaAad = {
            "ver": 2,
            "alg": "XCHACHA20-POLY1305",
            "mode": modeMarker,
            "suite": 3 if keyMode == 0 else 4,
            "kdfId": kdfId,
            "chunkSize": int(chunkSize),
            "origLen": len(rawBytes),
            "compLen": len(compBytes),
            "msgSeedDec": msgSeedDec,
        }
        cPart = xChaCha20Poly1305Encrypt(chunkKey, chunkNonce, p, buildChunkAad(metaAad, idx))
        packed = packPortableBytes(cPart)
        cipherParts.append(packed)
        lens.append(len(packed))

    bodyPacked = "".join(cipherParts)
    meta = {
        "ver": 2,
        "mode": modeMarker,
        "alg": "XCHACHA20-POLY1305",
        "suite": 3 if keyMode == 0 else 4,
        "kdfId": kdfId,
        "macId": 3,
        "flags": 7 if detached else 3,
        "chunkSize": int(chunkSize),
        "origLen": len(rawBytes),
        "compLen": len(compBytes),
        "lens": lens,
        "msgSeedDec": msgSeedDec,
        "saltHex": saltHex,
        "nonceHex": nonceHex,
        "ivHex": ivHex,
        "count": int(count),
        "cmp": 1 if compress else 0,
        "powBits": int(powBits),
    }
    meta["verify"] = computeVerifyToken(msgKeys["verifyRoot"], meta)
    meta["authTag"] = computeAuthTag(msgKeys["authRoot"], meta, bodyPacked, int(detached))
    if int(powBits) > 0:
        meta["powNonce"], meta["powHash"] = solvePow(meta, bodyPacked, int(powBits), int(powStart))
    else:
        meta["powNonce"], meta["powHash"] = 0, ""

    if detached:
        return {"meta": packPortableBytes(buildMetaCore(meta).encode("utf-8")), "body": bodyPacked}, hKey
    return encodeEnvelope(meta, bodyPacked), hKey

def decryptData(n, k, keyMode=None, count=8, meta=None):
    if isinstance(n, dict):
        metaObj = parseJson(unpackPortableBytes(n["meta"]).decode("utf-8"))
        bodyPacked = n["body"]
    elif meta is not None:
        metaObj = parseJson(unpackPortableBytes(meta).decode("utf-8")) if isinstance(meta, str) else dict(meta)
        bodyPacked = str(n)
    else:
        metaObj, bodyPacked = decodeEnvelope(n)

    modeValue = metaObj["mode"] if keyMode is None else int(keyMode)
    resolvedMode = 0 if int(modeValue) == 0 else 333
    hKey, _ = resolveKey(k, False, resolvedMode, count)

    saltHex = metaObj["saltHex"]
    nonceHex = metaObj["nonceHex"]
    ivHex = metaObj["ivHex"]
    msgKeys = deriveMessageKeys(hKey, saltHex, nonceHex, ivHex, resolvedMode, int(metaObj.get("count", count)))

    expectVerify = computeVerifyToken(msgKeys["verifyRoot"], metaObj)
    if not verifyEqual(expectVerify, metaObj.get("verify", "")):
        raise ValueError("wrong key or damaged ciphertext")
    expectAuth = computeAuthTag(msgKeys["authRoot"], metaObj, bodyPacked, 1 if (int(metaObj.get("flags", 0)) & 4) else 0)
    if not verifyEqual(expectAuth, metaObj.get("authTag", "")):
        raise ValueError("wrong key or damaged ciphertext")
    if not verifyPow(metaObj, bodyPacked):
        raise ValueError("invalid proof-of-work")

    parts = []
    pos = 0
    for L in metaObj["lens"]:
        part = bodyPacked[pos:pos + int(L)]
        if len(part) != int(L):
            raise ValueError("wrong key or damaged ciphertext")
        parts.append(part)
        pos += int(L)
    if pos != len(bodyPacked):
        raise ValueError("wrong key or damaged ciphertext")

    compOut = bytearray()
    metaAad = {
        "ver": int(metaObj["ver"]),
        "alg": metaObj["alg"],
        "mode": int(metaObj["mode"]),
        "suite": int(metaObj["suite"]),
        "kdfId": int(metaObj["kdfId"]),
        "chunkSize": int(metaObj["chunkSize"]),
        "origLen": int(metaObj["origLen"]),
        "compLen": int(metaObj["compLen"]),
        "msgSeedDec": metaObj["msgSeedDec"],
    }
    for idx, packed in enumerate(parts):
        chunkKey = bytes.fromhex(deriveBlockKey(msgKeys["encRoot"], idx, saltHex, nonceHex, ivHex))
        chunkNonce = deriveChunkNonce(msgKeys["nonceRoot"], idx, saltHex, nonceHex, ivHex)
        plain = xChaCha20Poly1305Decrypt(chunkKey, chunkNonce, unpackPortableBytes(packed), buildChunkAad(metaAad, idx))
        compOut.extend(plain)

    rawBytes = bytes(compOut)
    if int(metaObj.get("cmp", 0)) == 1:
        rawBytes = zlib.decompress(rawBytes)
    return decodeSafeText(rawBytes)

def generatePublicKey(k, keyMode=0, count=8):
    hKey, _ = resolveKey(k, False if k is not None else True, keyMode, count)
    seed = bytes.fromhex(deriveInternalKey(hKey, keyMode, count, "PUBSEED"))
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return packPortableBytes(pub)

def signData(data, k, keyMode=0, count=8):
    hKey, _ = resolveKey(k, False, keyMode, count)
    seed = bytes.fromhex(deriveInternalKey(hKey, keyMode, count, "PUBSEED"))
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    sig = priv.sign(payload)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"signature": packPortableBytes(sig), "publicKey": packPortableBytes(pub)}

def verifySignature(data, signature, publicKey):
    payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    sig = unpackPortableBytes(signature) if isinstance(signature, str) else bytes(signature)
    pub = unpackPortableBytes(publicKey) if isinstance(publicKey, str) else bytes(publicKey)
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)
        return True
    except Exception:
        return False
