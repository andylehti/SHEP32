import math
import sys
import re
from random import seed, randint
import string

# Remove the limit on the number of digits for integer string conversion
sys.set_int_max_str_digits(0)

# ======================
# Function E1/D1: gChar
# ======================
# - Description:
#     Generate a custom character set of length `c` from `string.printable`,
#     excluding certain special characters.
# - Inputs:
#     - `c`: The length of the character set to generate.
# - Returns:
#     - A string containing the custom character set of length `c`.
#
# Used in:
#     - Encryption Stage 1
#     - Decryption Stage 1
# ======================
def gChar(c):
    chars = ''.join([x for x in string.printable[:90] if x not in '/\\`"\',_!#$%&()* +-='])
    chars += '&()*$%/\\`"\',_!#'
    return chars[:c]

# ======================
# Function E2/D2: anyBase
# ======================
# - Description:
#     Convert an integer `n` to its string representation in base `b`.
# - Inputs:
#     - `n`: The integer number to convert.
#     - `b`: The base to convert to.
# - Returns:
#     - A string representing the number in base `b`.
#
# Used in:
#     - Encryption Stage 2
#     - Decryption Stage 2
# ======================
def anyBase(n, b):
    if n == 0:
        return '0'
    digits = []
    while n > 0:
        digits.append(str(n % b))
        n //= b
    return ' '.join(reversed(digits))

# ======================
# Function E3/D3: fromAnyBase
# ======================
# - Description:
#     Convert a string representation of a number in base `b` back to an integer.
# - Inputs:
#     - `nStr`: The string representation of the number.
#     - `b`: The base of the number.
# - Returns:
#     - The integer value of the number.
#
# Used in:
#     - Encryption Stage 3
#     - Decryption Stage 3
# ======================
def fromAnyBase(nStr, b):
    digits = nStr.split(' ')
    value = 0
    for digit in digits:
        value = value * b + int(digit)
    return value

# ======================
# Function E4/D4: fDecimal
# ======================
# - Description:
#     Convert an integer `d` to a string in base `b` using a custom character set.
# - Inputs:
#     - `d`: The integer to convert.
#     - `b`: The base to convert to.
# - Returns:
#     - A string representing the number in base `b` using the custom character set.
#
# Used in:
#     - Encryption Stage 4
#     - Decryption Stage 4
# ======================
def fDecimal(d, b):
    chars = gChar(b)
    s = ''
    while d > 0:
        s = chars[d % b] + s
        d //= b
    return s

# ======================
# Function E5/D5: tDecimal
# ======================
# - Description:
#     Convert a string `c` in base `b` back to an integer using a custom character set.
# - Inputs:
#     - `c`: The string representation of the number.
#     - `b`: The base of the number.
# - Returns:
#     - The integer value of the number.
#
# Used in:
#     - Encryption Stage 5
#     - Decryption Stage 5
# ======================
def tDecimal(c, b):
    chars = gChar(b)
    value = 0
    for ch in c:
        value = value * b + chars.index(ch)
    return value

# ======================
# Function E6: toBytes
# ======================
# - Description:
#     Convert a string `text` to its integer representation in base 256.
# - Inputs:
#     - `text`: The string to convert.
# - Returns:
#     - An integer representing the string in base 256.
#
# Used in:
#     - Encryption Stage 6
# ======================
def toBytes(text):
    return fromAnyBase(' '.join(str(ord(c)) for c in text), 256)

# ======================
# Function D6: fromBytes
# ======================
# - Description:
#     Convert an integer (in base 256) back to its string representation.
# - Inputs:
#     - `b`: The integer to convert.
# - Returns:
#     - The original string.
#
# Used in:
#     - Decryption Stage 6
# ======================
def fromBytes(b):
    return ''.join(chr(int(i)) for i in anyBase(b, 256).split())

# ======================
# Function E7/D7: generateSeries
# ======================
# - Description:
#     Generate a pseudo-random series of digits based on a seed value.
# - Inputs:
#     - `seedValue`: The seed value for the random number generator.
#     - `n`: The length of the series to generate.
# - Returns:
#     - A string of pseudo-random digits.
#
# Used in:
#     - Encryption Stage 7
#     - Decryption Stage 7
# ======================
def generateSeries(seedValue, n):
    seed(seedValue)
    return ''.join(str(randint(0, 8)) for _ in range(n))

# ======================
# Function E8: manipulateData
# ======================
# - Description:
#     Modify a string `s` using a pseudo-random series generated from `c`.
# - Inputs:
#     - `s`: The original string to manipulate.
#     - `c`: The seed value for generating the series.
# - Returns:
#     - A new string after manipulation.
#
# Used in:
#     - Encryption Stage 8
# ======================
def manipulateData(s, c):
    k = generateSeries(c, len(s))
    return ''.join(str((int(s[i]) + int(k[i])) % 10) for i in range(len(s)))

# ======================
# Function D8: inverseData
# ======================
# - Description:
#     Reverse the manipulation done by `manipulateData`.
# - Inputs:
#     - `s`: The manipulated string.
#     - `c`: The seed value used during manipulation.
# - Returns:
#     - The original string before manipulation.
#
# Used in:
#     - Decryption Stage 8
# ======================
def inverseData(s, c):
    k = generateSeries(c, len(s))
    return ''.join(str((int(s[i]) - int(k[i])) % 10) for i in range(len(s)))

# ======================
# Function E9: interject
# ======================
# - Description:
#     Interleave the first and second halves of a string `s`.
# - Inputs:
#     - `s`: The string to interleave.
# - Returns:
#     - The interleaved string.
#
# Used in:
#     - Encryption Stage 9
# ======================
def interject(s):
    if len(s) % 2:
        s, p = s[:-1], s[-1]
    else:
        p = ''
    mid = len(s) // 2
    return ''.join(s[i] + s[mid + i] for i in range(mid)) + p

# ======================
# Function D9: inverJect
# ======================
# - Description:
#     Reverse the interleaving done by `interject`.
# - Inputs:
#     - `s`: The interleaved string.
# - Returns:
#     - The original string before interleaving.
#
# Used in:
#     - Decryption Stage 9
# ======================
def inverJect(s):
    if len(s) % 2:
        s, p = s[:-1], s[-1]
    else:
        p = ''
    evenChars = s[::2]
    oddChars = s[1::2]
    return evenChars + oddChars + p

# ======================
# Function E10/D10: qRotate
# ======================
# - Description:
#     Rotate and reverse parts of a string `s`.
# - Inputs:
#     - `s`: The string to rotate.
# - Returns:
#     - The rotated string.
#
# Used in:
#     - Encryption Stage 10
#     - Decryption Stage 10
# ======================
def qRotate(s):
    return s[5:] + s[2:5][::-1] + s[:2]

# ======================
# Function E11/D11: pRotate
# ======================
# - Description:
#     Rotate and reverse parts of a string `s`.
# - Inputs:
#     - `s`: The string to rotate.
# - Returns:
#     - The rotated string.
#
# Used in:
#     - Encryption Stage 11
#     - Decryption Stage 11
# ======================
def pRotate(s):
    return s[-2:] + s[-5:-2][::-1] + s[:-5]

# ======================
# Function E12/D12: bSplit
# ======================
# - Description:
#     Split the binary representation of `n` into chunks, reverse each chunk,
#     and recombine into an integer.
# - Inputs:
#     - `n`: The integer to process.
#     - `f`: The size of each chunk (default is 4).
# - Returns:
#     - The integer after processing.
#
# Used in:
#     - Encryption Stage 12
#     - Decryption Stage 12
# ======================
def bSplit(n, f=4):
    s = bin(n)[3:]  # Remove '0b1' prefix
    chunks = [s[i:i+f][::-1] for i in range(0, len(s) - len(s) % f, f)]
    remainder = s[len(s) - len(s) % f:]
    result = '1' + ''.join(chunks) + remainder
    return int(result, 2)

# ======================
# Function E13/D13: addSpace
# ======================
# - Description:
#     Add a space at a specific position in a string `s`.
# - Inputs:
#     - `s`: The original string.
#     - `x`: The position where the space is to be added.
# - Returns:
#     - The string after adding the space.
#
# Used in:
#     - Encryption Stage 13
#     - Decryption Stage 13
# ======================
def addSpace(s, x):
    idx = s.rfind(' ') + 1 + (x + 1) if ' ' in s else x + 1
    return s[:idx] + ' ' + s[idx:]

# ======================
# Function E14/D14: kSplit
# ======================
# - Description:
#     Split a binary string `s` using digits in `k`.
# - Inputs:
#     - `s`: The integer to split.
#     - `k`: The key used for splitting.
# - Returns:
#     - The integer after splitting.
#
# Used in:
#     - Encryption Stage 14
#     - Decryption Stage 14
# ======================
def kSplit(s, k):
    s = bin(s)[3:]  # Remove '0b1' prefix
    k = str(k).replace('0', '')  # Remove zeros
    total = sum(int(d) for d in k)
    p = len(s) // total + len(k)
    k *= p
    for d in k:
        s1 = s
        s = addSpace(s, int(d))
        if s == s1:
            break
    reversedChunks = [x[::-1] for x in s.split()]
    return int('1' + ''.join(reversedChunks), 2)

# ======================
# Function E15/D15: keySplit
# ======================
# - Description:
#     Split an integer `n` using digits in `k`, with direction based on `y`.
# - Inputs:
#     - `n`: The integer to split.
#     - `k`: The key used for splitting.
#     - `y`: Direction indicator (1 or -1).
# - Returns:
#     - The integer after splitting.
#
# Used in:
#     - Encryption Stage 15
#     - Decryption Stage 15
# ======================
def keySplit(n, k, y=1):
    m = str(k) if y == 1 else str(k)[::-1]
    for d in m:
        n = bSplit(n, int(d) + 2)
    return n

# ======================
# Functions Used in processKey
# ======================

# Function Ap
def Ap(n, m, p):
    return str(int(n) * int(m))[:p]

# Function Bp
def Bp(n, p):
    return ''.join(str((int(n[i % len(n)]) + int(n[0])) % 10) for i in range(p))

# Function Cp
def Cp(n, m, p):
    return str(int(n) * int(n[:3 % len(n)]))[:p]

# Function Dp
def Dp(n, m, p):
    return (''.join(str(abs(int(n[i % len(n)]) * int(m[i % len(m)]))) for i in range(p)))[:p]

# Function Ep
def Ep(n, p):
    s = ''
    for i in range(p):
        num1 = int(n[i % len(n)]) + 1
        num2 = int(n[(i + 1) % len(n)]) + 1
        val = math.pi * (1 / num1) / num2
        s += str(val - int(val))[2:]
    total = sum(int(c) for c in s)
    return str(total)[-p:]

# ======================
# Function E16/D16: processKey
# ======================
# - Description:
#     Process a key `n` with an optional modifier `m`.
# - Inputs:
#     - `n`: The key to process.
#     - `m`: An optional modifier (default is 0).
# - Returns:
#     - A new processed key as a string.
#
# Used in:
#     - Encryption Stage 16
#     - Decryption Stage 16
# ======================
def processKey(n, m=0):
    n, m = str(n), str(m) if m else str(n)
    p = len(n)
    r = int(n[0])
    tIndex = int(m[int(n[0])]) % p if len(m) > int(n[0]) else -1
    t = int(n[tIndex]) if tIndex >= 0 else int(n[-1])
    a = (r + t) % 6
    b = (r - t) % 6

    # First operation based on a
    if a == 0:
        n = Ap(n, m, p)
    elif a == 1:
        n = Bp(n, p)
    elif a == 2:
        n = Cp(n, m, p)
    elif a == 3:
        n = Dp(n, m, p)
    elif a == 4:
        n = Ep(n, p)
    else:
        n = Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p)

    # Second operation based on b
    if b == 0:
        n = Cp(n, m, p)
    elif b == 1:
        n = Dp(n, m, p)
    elif b == 2:
        n = Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p)
    elif b == 3:
        n = Bp(n, p)
    elif b == 4:
        n = Ap(n, m, p)
    else:
        n = Ap(Bp(Cp(Dp(Ep(n, p), m, p), m, p), p), m, p)

    # Extract digits a and b for further processing
    aDigit = next((x for x in n if x.isdigit() and x != '0'), '2')
    bDigit = next((x for x in n[n.index(aDigit) + 1:] if x.isdigit() and x != '0'), '3')

    # Additional transformations
    n = str(bSplit(bSplit(int(n) + int(pRotate(n)))))
    n = tDecimal(qRotate(str(n)), 10)
    n = str(int(int(n) + int(aDigit + bDigit + '0' * (p - 2))) + int(m))[-p:]
    return n

# ======================
# Function E17: manipulateKey
# ======================
# - Description:
#     Manipulate a key `n` to generate a hash key.
# - Inputs:
#     - `n`: The key to manipulate.
# - Returns:
#     - A string representing the manipulated key.
#
# Used in:
#     - Encryption Stage 17
# ======================
def manipulateKey(n):
    hex_n = hex(n)[2:]
    return fDecimal(tDecimal(hex_n, 16) + int(fDecimal(n, 16), 16), 16)[-63:-1]

# ======================
# Function E18: getKey
# ======================
# - Description:
#     Generate a key from a number `n`.
# - Inputs:
#     - `n`: The number to generate the key from.
#     - `x`: Maximum length of the key (default is 78).
# - Returns:
#     - A string representing the generated key.
#
# Used in:
#     - Encryption Stage 18
# ======================
def getKey(n, x=78):
    while True:
        n = (n // 8) + int(Ep(str(n // 5), len(str(n))))
        if len(str(n)) <= x:
            return str(n)

# ======================
# Function E19: fetchKey
# ======================
# - Description:
#     Fetch a hash key based on a number `n`.
# - Inputs:
#     - `n`: The number to base the key on.
# - Returns:
#     - A string representing the hash key.
#
# Used in:
#     - Encryption Stage 19
# ======================
def fetchKey(n):
    initial_n = n + 90
    i = (n % 7) + 1
    checked_data = checkData(initial_n, i)
    manipulated_data = manipulateData(getKey(checked_data, 79), n)
    manipulated_int = tDecimal(manipulated_data, 10)
    return manipulateKey(manipulated_int)

# ======================
# Function E20: checkData
# ======================
# - Description:
#     Modify a number `n` to ensure it's at least length 80.
# - Inputs:
#     - `n`: The number to check.
#     - `i`: An incrementing value.
# - Returns:
#     - An integer after processing.
#
# Used in:
#     - Encryption Stage 20
# ======================
def checkData(n, i):
    while len(str(n)) < 80:
        n *= 3
        n += i
        i += i
    n_list = [int(str(n)[j:j + 80]) for j in range(0, len(str(n)), 80)]
    n_sum = sum(n_list)
    rotated = qRotate(str(bSplit(n_sum)))
    processed = int(rotated) + int(processKey(n_sum))
    return kSplit(processed, n_sum)

# ======================
# Function E21/D17: baseSplit
# ======================
# - Description:
#     Modify a number `n` using base `b` and key `k`, depending on `y`.
# - Inputs:
#     - `n`: The number to modify.
#     - `k`: The key used in modification.
#     - `b`: The base used for splitting (default is 1543).
#     - `y`: Direction indicator (1 or -1).
# - Returns:
#     - An integer after modification.
#
# Used in:
#     - Encryption Stage 21
#     - Decryption Stage 17
# ======================
def baseSplit(n, k, b=1543, y=1):
    n_str = anyBase(n, b)
    y = 1 if y == 1 else -1
    m = 2**16
    s = ' '.join(x for x in anyBase(k, m).split() if 2 <= len(x) <= 10) + ' '
    n_counts = len(n_str.split())
    s_counts = 0
    while s_counts < n_counts:
        last_s = int(s.split()[-1]) + m
        s += ' '.join(x for x in anyBase(k, last_s).split() if 2 <= len(x) <= 10) + ' '
        s_counts = len(s.split())
    n_list = n_str.split()
    s_list = s.split()
    result = ' '.join(str((int(x) + (int(z)) * y) % b) for x, z in zip(n_list, s_list))
    return fromAnyBase(result, b)

# ======================
# Core Functions
# ======================

# ======================
# Function E22: pData
# ======================
# - Description:
#     Process data `n` with a list of keys for encryption.
# - Inputs:
#     - `n`: The data to encrypt.
#     - `keys`: A list of keys for encryption steps.
#     - `b`: Base value used in processing.
# - Returns:
#     - The encrypted data.
#
# Used in:
#     - Encryption Stage 22
# ======================
def pData(n, keys, b):
    for key in keys:
        n = keySplit(n, key, 1)
        manipulated = manipulateData(str(n), key)
        n = tDecimal(manipulated, 10)
        n = baseSplit(int(n), key, b, 1)
        n = kSplit(n, str(key))
        if int(str(key)[0]) % 2 == 1:
            n = int(interject(str(n)))
    return n

# ======================
# Function D18: dData
# ======================
# - Description:
#     Process data `n` with a list of keys for decryption.
# - Inputs:
#     - `n`: The data to decrypt.
#     - `keys`: A list of keys for decryption steps.
#     - `b`: Base value used in processing.
# - Returns:
#     - The decrypted data.
#
# Used in:
#     - Decryption Stage 18
# ======================
def dData(n, keys, b):
    for key in reversed(keys):
        if int(str(key)[0]) % 2 == 1:
            n = int(inverJect(str(n)))
        n = kSplit(n, str(key))
        n = fDecimal(baseSplit(int(n), key, b, 0), 10)
        n = inverseData(n, key)
        n = keySplit(int(n), key, 0)
    return n

# ======================
# Function E23: encryptData
# ======================
# - Description:
#     Encrypt data `n` with an optional key `k` and mode `m`.
# - Inputs:
#     - `n`: The data to encrypt (string).
#     - `k`: Optional key (default is 0).
#     - `m`: Mode indicator (default is 0).
# - Returns:
#     - A tuple containing the encrypted data and the hash key.
#
# Used in:
#     - Encryption Stage 23
# ======================
def encryptData(n, k=0, m=0):
    n = toBytes(n)
    if k < 1:
        hKey = fetchKey(n)
    else:
        if m == 1 and k >= 11100000:
            hKey = fDecimal(k, 16)
        else:
            hKey = fetchKey(k)
    key = tDecimal(hKey, 16)
    b = 1543
    keys = [key]
    for _ in range(9):
        key = int(processKey(key))
        keys.append(key)
    n += key // b
    n = pData(n, keys, b)
    return fDecimal(n, 62), hKey

# ======================
# Function D19: decryptData
# ======================
# - Description:
#     Decrypt data `n` with key `k`.
# - Inputs:
#     - `n`: The data to decrypt (string).
#     - `k`: The key used for decryption.
# - Returns:
#     - The original decrypted data as a string.
#
# Used in:
#     - Decryption Stage 19
# ======================
def decryptData(n, k):
    key = tDecimal(k, 16)
    b = 1543
    n = tDecimal(n, 62)
    keys = [key]
    for _ in range(9):
        key = int(processKey(key))
        keys.append(key)
    n = dData(n, keys, b)
    n -= key // b
    return fromBytes(n)

if __name__ == "__main__":
    n = 'Andrew Lehti'
    k = 8657523846634763573364787454663748570
    encryptedData, key = encryptData(n, k, 0)
    print(f"Encrypted Data: {encryptedData}\nKey: {key}")
    decryptedData = decryptData(encryptedData, key)
    print(f"Decrypted Data: {decryptedData}")
