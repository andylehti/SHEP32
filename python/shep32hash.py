import math, os, sys, time

sys.set_int_max_str_digits(0)

# ================
# USAGE
# ================

# if importing from script
# from shep32hash import shep32Hash

# print(shep32Hash("hello"))
# print(shep32Hash("hello", 0))
# print(shep32Hash("hello", 1))

def shep32Hash(value=None, mode=0):
    return generatePrimaryKey(value) if int(mode) == 0 else generateExtendedKey(value)

# ================
# CORE
# ================

tDecCache = {}
gCharBase = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:;<>?@[]^&()*$%/\\`\"',_!#"
gAuxBase = "ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def deriveCharset(c): return gCharBase[:c]
def deriveAuxCharset(): return gAuxBase
def extractTokens(s): return s.split()
def encodeHex(n): return format(int(n), "x")
def dropPrefixBit(n):
    b = format(int(n), "b")
    return "" if len(b) <= 1 else b[1:]
def leftPad(v, w): return str(int(v)).zfill(int(w))
def truncatePrefix(v, n):
    s = str(v)
    n = int(n)
    if n <= 0: return ""
    if len(s) >= n: return s[:n]
    return s + ("0" * (n - len(s)))

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

def encodeSentinel(b):
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise ValueError("encodeSentinel expects bytes")
    bb = b"\x01" + bytes(b)
    return int.from_bytes(bb, "big")

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
    return prefixProduct(biasTransform(prefixSquare(digitProduct(integratePi(state, width), key, width), key, width), width), key, width)

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
    return {"input": start, "first": first, "firstPad": firstPad, "second": second, "third": third, "packedLen": packedLen, "fourth": fourth, "left": left, "mix": mix, "right": right, "value": value}

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
        return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24) | (b[i + 4] << 32) | (b[i + 5] << 40) | (b[i + 6] << 48) | (b[i + 7] << 56)) & m
    m = 0xFFFFFFFFFFFFFFFF
    data = bytearray(str(h).encode("utf-8"))
    n = len(data)
    bitLen = (n * 8) & m
    data.append(0x80)
    while len(data) % 128 != 112:
        data.append(0)
    lenA = mix(bitLen ^ n ^ 0x9E3779B97F4A7C15)
    lenB = mix(((bitLen << 1) ^ n ^ 0xC2B2AE3D27D4EB4F) & m)
    for i in range(8): data.append((bitLen >> (8 * i)) & 0xFF)
    for i in range(8): data.append((lenA >> (8 * i)) & 0xFF)
    for i in range(8): data.append((lenB >> (8 * i)) & 0xFF)
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
        x0 = word(data, off + 0); x1 = word(data, off + 8); x2 = word(data, off + 16); x3 = word(data, off + 24)
        x4 = word(data, off + 32); x5 = word(data, off + 40); x6 = word(data, off + 48); x7 = word(data, off + 56)
        x8 = word(data, off + 64); x9 = word(data, off + 72); x10 = word(data, off + 80); x11 = word(data, off + 88)
        x12 = word(data, off + 96); x13 = word(data, off + 104); x14 = word(data, off + 112); x15 = word(data, off + 120)
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

def bindState(trace, modeId="32"):
    parts = [str(modeId), truncatePrefix(trace["input"], 24), truncatePrefix(trace["first"], 96), truncatePrefix(trace["firstPad"], 96), truncatePrefix(trace["second"], 96), truncatePrefix(trace["third"], 96), truncatePrefix(trace["fourth"], 96), truncatePrefix(trace["left"], 96), truncatePrefix(trace["mix"], 96), truncatePrefix(trace["right"], 96), truncatePrefix(trace["value"], 96)]
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
