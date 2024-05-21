import streamlit as st
import math
from random import seed, randint
import string
import sys
import re
sys.set_int_max_str_digits(0)

def encryptData(n, k=0, m=0):
    n = toBytes(n)
    hKey = fetchKey(n) if k < 10000 else (fDecimal(k, 16) if m == 1 and k >= 10000 else fetchKey(k))
    key, b = tDecimal(hKey, 16), 1543
    keys, n = [key] + [key := int(processKey(key)) for _ in range(9)], n + (key // b)
    n = pData(n, keys, b)
    return fDecimal(n, 62), hKey

def decryptData(n, k):
    key, b, n = tDecimal(k, 16), 1543, tDecimal(n, 62)
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

def toBytes(t): return fromAnyBase(' '.join(str(ord(c)) for c in t), 256)
def fromBytes(b): return ''.join(chr(int(i)) for i in anyBase(b, 256).split())
def fetchKey(n): return manipulateKey(tDecimal(manipulateData(getKey(checkData(n+90, (n % 7) + 1), 79), n), 10))
def manipulateKey(n): return fDecimal(tDecimal(hex(n)[2:], 16) + int(fDecimal(n, 16), 16), 16)[-63:-1]
def getKey(n, x=78): return next(str(n) for _ in iter(int, 1) if len(str(n := (n // 8) + int(Ep(str(n // 5), len(str(n)))))) <= x)
def anyBase(n, b): return '0' if n == 0 else ' '.join(str(n // b ** i % b) for i in range(int(math.log(n, b)), -1, -1))
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

def baseSplit(n, k, b=1543, y=1):
    n, y, m = anyBase(n, b), 1 if y == 1 else -1, 2**16
    sCounts, nCounts, s = 0, len((n).split()), ' '.join(x for x in anyBase(k, m).split() if 2 <= len(x) <= 10) + ' '
    while sCounts < nCounts: s += ' '.join(x for x in anyBase(k, (int(s.split()[-1]) + m)).split() if 2 <= len(x) <= 10) + ' '; sCounts = len(s.split())
    return fromAnyBase(' '.join(str((int(x) + (int(z)) * y) % int(b)) for x, z in zip(n.split(), s.split())), b)

def sanitizeInput(t):
    return re.sub(r'[^a-zA-Z0-9]', '', t)

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
    key_input = st.text_input("Key: (optional: decimal format only)", '')
    sanitized_key = ''.join(filter(str.isdigit, key_input))
    k = int(sanitized_key) if sanitized_key else 0
    use_verbatim = st.checkbox("Use key verbatim: only valid if key is larger than 10000")
    m = 1 if use_verbatim else 0
    if st.button("Encrypt Data"):
        if s:
            e, k = encryptData(s, k, m)
            st.markdown("**Key:**")
            st.markdown(f'{k}')
            st.markdown("**Encrypted data:**")
            st.markdown(f'{e}')
            st.markdown("**Combined Data + Key:**\n")
            st.markdown("for demonstration purposes only")
            combined = fDecimal(tDecimal(e, 62), 61) + 'Z' + fDecimal(tDecimal(k, 16), 61)
            st.markdown(f'{combined}')
            st.markdown("**Decrypted data:**")
            st.html(f'<p style="white-space: pre-wrap; overflow-wrap: break-word; overflow: hidden;">{decryptData(e, k)}</p>')

elif st.session_state.mode == 'Decrypt':
    st.title("Decryption:")
    d = st.text_input("Enter data to decrypt:", "")
    r = st.text_input("Enter key:", "")
    d = sanitizeInput(d)
    r = sanitizeInput(r)
    if d and r:
        st.markdown("**Decrypted data:**")
        st.html(f'<p style="white-space: pre-wrap; overflow-wrap: break-word; overflow: hidden;">{decryptData(d, r)}</p>')

elif st.session_state.mode == 'Combined Decryption':
    st.title("Combined String Decryption:")
    q = st.text_input("Enter combined string data:", "")
    q = sanitizeInput(q)
    if 'Z' in q:
        v, w = q.split('Z')
        w = fDecimal(tDecimal(w, 61), 16)
        v = fDecimal(tDecimal(v, 61), 62)
        if v and w:
            st.markdown("**Decrypted data:**")
            st.html(f'<p style="white-space: pre-wrap; overflow-wrap: break-word; overflow: hidden;">{decryptData(v, w)}</p>')

footer = f"""
<div class="footer">
    <p>GitHub Repository: <a href="https://github.com/andylehti/SHEP32" target="_blank">SHEP-32</a> | <a href="https://x.com/andylehti" target="_blank">Author</a></p>
</div>
"""
st.markdown(footer, unsafe_allow_html=True)
