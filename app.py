import streamlit as st
#22
import math
from random import seed, randint
import string
import sys
import re
sys.set_int_max_str_digits(0)

def encryptData(n, k=0):
    n = toBytes(n)
    hKey, e = getB(fetchKey(n))
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
    while len(str(n)) < 80: n *= 3; n, i = n + i, i + i
    n = sum(int(str(n)[i:i+80]) for i in range(0, len(str(n)), 80))
    return kSplit((int(qRotate(str(bSplit(n))) + processKey(n))), n)

def toBytes(t):
    b = b"\x01" + t.encode("utf-16-le", errors="surrogatepass")
    return fromAnyBase(" ".join(str(x) for x in b), 256)

def fromBytes(n):
    b = bytes(int(i) for i in anyBase(n, 256).split())
    if not b or b[0] != 1:
        raise ValueError("byte sentinel missing")
    b = b[1:]
    return b.decode("utf-16-le", errors="surrogatepass")

def anyBase(n, b):
    if n == 0: return '0'
    d=[]
    while n: d.append(str(n%b)); n//=b
    return ' '.join(d[::-1])

def fetchKey(n): return manipulateKey(tDecimal(manipulateData(getKey(checkData(n+90, (n % 7) + 1), 79), n), 10))
def manipulateKey(n): return fDecimal(tDecimal(hex(n)[2:], 16) + int(fDecimal(n, 16), 16), 16)[-63:-1]
def getKey(n, x=78): return next(str(n) for _ in iter(int, 1) if len(str(n := (n // 8) + int(Ep(str(n // 5), len(str(n)))))) <= x)
def fromAnyBase(n, b): return sum(int(c) * b ** i for i, c in enumerate(reversed(n.split(' '))))
def gChar(c): b = ''.join([x for x in string.printable[:90] if x not in '/\\`"\',_!#$%&()* +-=']) + '&()*$%/\\`"\',_!#'; return b[:c]
def generateSeries(s, n): seed(s); return ''.join(str(randint(0, 8)) for _ in range(n))
def manipulateData(s, c): k = generateSeries(c, len(str(s))); return ''.join(str((int(s[i]) + int(k[i])) % 10) for i in range(len(s)))
def inverseData(s, c): k = generateSeries(c, len(str(s))); return ''.join(str((int(s[i]) - int(k[i])) % 10) for i in range(len(s)))
def qRotate(s): return s[5:] + s[2:5][::-1] + s[:2]
def pRotate(s): return s[-2:] + s[-5:-2][::-1] + s[:-5]
def interject(s): s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, ''); return ''.join(x + y for x, y in zip(s[:len(s) // 2], s[len(s) // 2:])) + p
def inverJect(s): s, p = (s[:-1], s[-1]) if len(s) % 2 else (s, ''); h = len(s) // 2; return ''.join(s[i] for i in range(0, len(s), 2)) + ''.join(s[i] for i in range(1, len(s), 2)) + p
def keySplit(n, k, y=1): m = str(k) if y == 1 else str(k)[::-1]; return [n := bSplit(n, int(d) + 2) for d in m][-1]
def bSplit(s, f=4): s = bin(s)[3:]; return int('1' + ''.join(s[i:i+f][::-1] for i in range(0, len(s) - len(s) % f, f)) + s[len(s) - len(s) % f:], 2)
def addSpace(s, x): return s[:s.rfind(' ')+1+(x+1)] + ' ' + s[s.rfind(' ')+1+(x+1):] if ' ' in s else s[:(x+1)] + ' ' + s[(x+1):]
    
def kSplit(s, k):
    s, k = bin(s)[3:], str(k)
    k = k.replace('0', ''); p = len(s) // sum(int(d) for n in k for d in str(n)) + len(k); k = k * p
    for d in k:
        s1 = s; s = addSpace(s, int(d))
        if s == s1: break
    return int('1' + ''.join([x[::-1] for x in s.split()]), 2)

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
    a, b = next((x for x in n if x.isdigit() and x != '0'), '2'), next((x for x in n[n.index(n)+1:] if x.isdigit() and x != '0'), '3')
    n = str(bSplit(bSplit(int(n) + int(pRotate(n)))))
    n = tDecimal(qRotate(str(n)), 10)
    return str(int(int(n) + int(a + b + '0' * (p-2))) + int(m))[-p:]

def gChar(c): b = ''.join([x for x in string.printable[:90] if x not in '/\\`"\',_!#$%&()* +-=']) + '&()*$%/\\`"\',_!#'; return b[:c]

def fDecimal(d, b):
    c, n, r, s = gChar(b), 1, d, ""
    while r >= b ** n: r -= b ** n; n += 1
    while r > 0: s = c[r % b] + s; r //= b
    return s.zfill(n)

def tDecimal(c, b):
    chars, v, l = gChar(b), 0, len(str(c))
    v += sum(chars.index(ch) * (b ** i) for i, ch in enumerate(reversed(str(c))))
    return v + sum(b ** i for i in range(1, l))

def baseSplit(n, k, b=8, y=1):
    m = 2 ** 16
    nDigits = anyBase(n, b).split()
    s = ' '.join(x for x in anyBase(k, m).split() if 2 <= len(x) <= 10) + ' '

    if not s.split():
        s = f'{(k % (m - 2)) + 2} '

    cap = (len(nDigits) + 2) * 40
    loops = 0

    if y == 1:
        while len(s.split()) < len(nDigits) + 1:
            last = int(s.split()[-1])
            s += ' '.join(x for x in anyBase(k, last + m).split() if 2 <= len(x) <= 10) + ' '
            loops += 1
            if loops > cap:
                break

        z = s.split()
        if len(z) < len(nDigits) + 1:
            need = len(nDigits) + 1 - len(z)
            z += [z[-1]] * need

        z0 = int(z[0]) % b
        guard = (1 - z0) % b
        nDigits = [str(guard)] + nDigits
        return fromAnyBase(' '.join(str((int(x) + int(zv)) % b) for x, zv in zip(nDigits, z)), b)

    while len(s.split()) < len(nDigits):
        last = int(s.split()[-1])
        s += ' '.join(x for x in anyBase(k, last + m).split() if 2 <= len(x) <= 10) + ' '
        loops += 1
        if loops > cap:
            break

    z = s.split()
    if len(z) < len(nDigits):
        need = len(nDigits) - len(z)
        z += [z[-1]] * need

    outDigits = [str((int(x) - int(zv)) % b) for x, zv in zip(nDigits, z)]
    return 0 if len(outDigits) <= 1 else fromAnyBase(' '.join(outDigits[1:]), b)

def fold64(h):
    h = ''.join(c for c in h.lower() if c in '0123456789abcdef')
    if not h:
        return '0' * 64
    if len(h) < 64:
        h = (h * ((64 // len(h)) + 1))
        return h
    out = [0] * 64
    for i, ch in enumerate(h):
        out[i % 64] ^= int(ch, 16)
    return ''.join('0123456789abcdef'[x] for x in out)

def getE(hex64):
    x = hex64.lower().zfill(64)[-64:]
    s4 = (str(int(x[:4], 16) + int(x[-4:], 16)).lstrip('0') or '0')[:4]
    n = int(s4)
    if n < 4096:
        return n
    if n % 2 == 0:
        t = s4[:-1]
        return int(t) + (100 if len(s4) > 1 and s4[-2] == "0" else 0)
    t = s4[1:]
    return int(t) + (100 if len(s4) > 1 and s4[1] == "0" else 0)

def getB(hexStr):
    h = fold64(hexStr)

    f = int(h[:4], 16)
    l = int(h[-4:], 16)
    seed = ((f >> 8) ^ (l & 0xFF) ^ (f & 0xFF) ^ (l >> 8)) & 0xFF

    mh = ''.join(f'{((int(h[i:i+2], 16) - seed) & 0xFF):02x}' for i in range(0, 64, 2))

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
