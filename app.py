#29B
import streamlit as st
import math, os, sys, time, string, hashlib, base64, re
from random import seed, randint, choice
from collections import Counter

sys.set_int_max_str_digits(0)

# =========================
# SHEP32 CORE
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

def fast_anyBase_list(val, b):
    if val == 0: return ['0']
    
    # Precise doubling search to find actual bounding target
    powers = [(1, b)]
    while powers[-1][1] <= val:
        powers.append((powers[-1][0] * 2, powers[-1][1] ** 2))
        
    n = 0
    cur_bn = 1
    for p_n, p_val in reversed(powers):
        if cur_bn * p_val <= val:
            cur_bn *= p_val
            n += p_n
    n += 1

    def _convert(v, target_len):
        if target_len <= 500:
            out = []
            for _ in range(target_len):
                out.append(str(v % b))
                v //= b
            return out[::-1]
        
        half = target_len // 2
        divisor = b ** half
        upper_val, lower_val = divmod(v, divisor)
        return _convert(upper_val, target_len - half) + _convert(lower_val, half)

    res = _convert(val, n)
    while len(res) > 1 and res[0] == '0':
        res.pop(0)
    return res

def anyBase(n, b):
    return ' '.join(fast_anyBase_list(n, b))

def fromAnyBase(n, b):
    parts = n.split() if isinstance(n, str) else n
    if not parts: return 0
    ints = [int(p) for p in parts]
    
    def _eval(start, end):
        if end - start <= 200:
            res = 0
            for i in range(start, end):
                res = res * b + ints[i]
            return res
        mid = (start + end) // 2
        return _eval(start, mid) * (b ** (end - mid)) + _eval(mid, end)
        
    return _eval(0, len(ints))

def fast_base_convert(val, b, pad_to, charset):
    if pad_to <= 500:
        out = []
        for _ in range(pad_to):
            out.append(charset[val % b])
            val //= b
        return ''.join(reversed(out))
        
    half = pad_to // 2
    divisor = b ** half
    upper_val, lower_val = divmod(val, divisor)
    upper_str = fast_base_convert(upper_val, b, pad_to - half, charset)
    lower_str = fast_base_convert(lower_val, b, half, charset)
    return upper_str + lower_str

def fDecimal(d, b):
    c = gChar(b)
    if b == 1:
        return c[0] * (d + 1)
        
    target = d * (b - 1) + b
    
    powers = [(1, b)]
    while powers[-1][1] <= target:
        powers.append((powers[-1][0] * 2, powers[-1][1] ** 2))
        
    n = 0
    cur_bn = 1
    for p_n, p_val in reversed(powers):
        if cur_bn * p_val <= target:
            cur_bn *= p_val
            n += p_n
            
    geom_sum = (b ** n - b) // (b - 1) if n > 0 else 0
    r = d - geom_sum
    
    if n == 0: return ""
    return fast_base_convert(r, b, n, c)

def tDecimal(c, b):
    s = str(c)
    l = len(s)
    if b == 10:
        return int(s) + ((10 ** l - 10) // 9 if l > 1 else 0)
    if b == 16:
        return int(s, 16) + ((16 ** l - 16) // 15 if l > 1 else 0)
        
    if b not in _TDEC_CACHE: _TDEC_CACHE[b] = {ch: i for i, ch in enumerate(gChar(b))}
    char_map = _TDEC_CACHE[b]
    
    def _eval(start, end):
        if end - start <= 200:
            res = 0
            for i in range(start, end):
                res = res * b + char_map[s[i]]
            return res
        mid = (start + end) // 2
        return _eval(start, mid) * (b ** (end - mid)) + _eval(mid, end)
    
    v = _eval(0, l)
    geom_sum = (b ** l - b) // (b - 1) if b > 1 and l > 1 else (l - 1 if b == 1 and l > 1 else 0)
    return v + geom_sum

# --- ASCII/Binary Optimizations ---

def hashKey(n): return getB(fetchKey(n))
def fetchKey(n): return manipulateKey(tDecimal(manipulateData(getKey(checkData(n+90, (n % 7) + 1), 79), n), 10))
def manipulateKey(n): return fDecimal(tDecimal(hex(n)[2:], 16) + int(fDecimal(n, 16), 16), 16)[-63:-1]
def getKey(n, x=78): return next(str(n) for _ in iter(int, 1) if len(str(n := (n // 8) + int(Ep(str(n // 5), len(str(n)))))) <= x)

def generateSeries(s, n): 
    seed(s)
    r = randint
    return ''.join(str(r(0, 8)) for _ in range(n))

def manipulateData(s, c): 
    s_str = str(s)
    k = generateSeries(c, len(s_str))
    return ''.join(chr(((ord(a) + ord(b) - 96) % 10) + 48) for a, b in zip(s_str, k))

def inverseData(s, c): 
    s_str = str(s)
    k = generateSeries(c, len(s_str))
    return ''.join(chr(((ord(a) - ord(b)) % 10) + 48) for a, b in zip(s_str, k))

def qRotate(s): return s[5:] + s[2:5][::-1] + s[:2]
def pRotate(s): return s[-2:] + s[-5:-2][::-1] + s[:-5]

def interject(s): 
    s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, '')
    h = len(s) // 2
    return ''.join(x + y for x, y in zip(s[:h], s[h:])) + p

def inverJect(s): 
    s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, '')
    return ''.join(s[i] for i in range(0, len(s), 2)) + ''.join(s[i] for i in range(1, len(s), 2)) + p

def keySplit(n, k, y=1): 
    m = str(k) if y == 1 else str(k)[::-1]
    for d in m: n = bSplit(n, int(d) + 2)
    return n

def bSplit(s, f=4): 
    b_str = bin(s)[3:]
    l = len(b_str)
    rem = l % f
    res = ['1']
    res.extend(b_str[i:i+f][::-1] for i in range(0, l - rem, f))
    if rem: res.append(b_str[l-rem:])
    return int(''.join(res), 2)

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

def baseSplit(n, k, b=8, y=1):
    m = 2 ** 16
    nDigits = fast_anyBase_list(n, b)
    z = [x for x in fast_anyBase_list(k, m) if 2 <= len(x) <= 10]
    if not z: z = [str((k % (m - 2)) + 2)]

    cap = (len(nDigits) + 2) * 40
    loops = 0
    target_len = len(nDigits) + 1 if y == 1 else len(nDigits)

    while len(z) < target_len:
        next_k = int(z[-1]) + m
        z.extend(x for x in fast_anyBase_list(next_k, m) if 2 <= len(x) <= 10)
        loops += 1
        if loops > cap: break

    if len(z) < target_len: z.extend([z[-1]] * (target_len - len(z)))

    if y == 1:
        guard = (1 - (int(z[0]) % b)) % b
        nDigits = [str(guard)] + nDigits
        return fromAnyBase([str((int(x) + int(zv)) % b) for x, zv in zip(nDigits, z)], b)

    outDigits = [str((int(x) - int(zv)) % b) for x, zv in zip(nDigits, z)]
    return 0 if len(outDigits) <= 1 else fromAnyBase(outDigits[1:], b)

def Ap(n, m, p): return str(int(n) * int(m))[:p]
def Bp(n, p): 
    n0 = ord(n[0]) - 48
    return ''.join(chr(((ord(n[i % len(n)]) - 48 + n0) % 10) + 48) for i in range(p))
def Cp(n, m, p): return str(int(n) * int(n[:3 % len(n)]))[:p]
def Dp(n, m, p): 
    ln, lm = len(n), len(m)
    return (''.join(str(abs((ord(n[i % ln]) - 48) * (ord(m[i % lm]) - 48))) for i in range(p)))[:p]
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

def shepKeyFromString(s): return getB(fetchKey(toBytes(s)))[0].lower()
    
def cleanToken(t):
    return re.sub(r'\s+', '', t or '')

st.set_page_config(page_title="SHEP-32: Series Hashing Encryption Protocol", page_icon="🔒")

st.markdown(
    """
    <style>
    .reportview-container .main footer {visibility: hidden;}
    [data-testid="stBlock"] {margin-bottom: -100px;}
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: white;
        color: black;
        text-align: center;
        padding: 10px;
        border-top: 1px solid #e1e4e8;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.subheader('SHEP-32: Series Hashing Encryption Protocol', divider='rainbow')

if 'mode' not in st.session_state:
    st.session_state.mode = 'Encrypt'

col1, col2, col3 = st.columns(3)
with col1:
    if st.button("Encrypt"):
        st.session_state.mode = 'Encrypt'
with col2:
    if st.button("Decrypt"):
        st.session_state.mode = 'Decrypt'
with col3:
    if st.button("Combined Decryption"):
        st.session_state.mode = 'Combined Decryption'

if st.session_state.mode == 'Encrypt':
    st.title("Encryption:")
    s = st.text_area('Enter data to encrypt:', '', height=150)
    if st.button("Encrypt Data") and s:
        e, k = encryptData(s)
        st.markdown("**Key:**")
        st.code(k)
        st.markdown("**Encrypted data:**")
        st.code(e)
        st.markdown("**Decrypted data:**")
        st.markdown(f"<div style='white-space: pre-wrap; overflow-wrap: break-word;'>{decryptData(e, k)}</div>", unsafe_allow_html=True)
        st.divider()
        st.markdown("**Combined Data + Key:**")
        st.caption("for demonstration purposes only")
        combined = fDecimal(tDecimal(e, 62), 61) + 'Z' + fDecimal(tDecimal(k, 16), 61)
        st.code(combined)

elif st.session_state.mode == 'Decrypt':
    st.title("Decryption:")
    d = cleanToken(st.text_input("Enter data to decrypt:", ""))
    r = cleanToken(st.text_input("Enter key:", ""))
    if d and r:
        st.markdown("**Decrypted data:**")
        st.markdown(f"<div style='white-space: pre-wrap; overflow-wrap: break-word;'>{decryptData(d, r)}</div>", unsafe_allow_html=True)

elif st.session_state.mode == 'Combined Decryption':
    st.title("Combined String Decryption:")
    q = cleanToken(st.text_input("Enter combined string data:", ""))
    if 'Z' in q:
        v, w = q.split('Z', 1)
        w = fDecimal(tDecimal(w, 61), 16)
        v = fDecimal(tDecimal(v, 61), 62)
        if v and w:
            st.markdown("**Decrypted data:**")
            st.markdown(f"<div style='white-space: pre-wrap; overflow-wrap: break-word;'>{decryptData(v, w)}</div>", unsafe_allow_html=True)

footer = """
<div class="footer">
    <p>GitHub Repository: <a href="https://github.com/andylehti/SHEP32" target="_blank">SHEP-32</a></p>
</div>
"""
st.markdown(footer, unsafe_allow_html=True)
