#24A
import math, os, sys, time, string, hashlib, base64, streamlit
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
