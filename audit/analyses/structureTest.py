import hashlib

def hashData(i):
    return hashlib.sha256(str(i).encode()).hexdigest()

def findDuplicate():
    keys, hashes = set(), set()
    i, f = 1, 1
    while f <= 10:
        k, h = hashKey(i), hashData(i)
        if k[:f] in keys:
            f += 1
            print(i, k[:f], 'SHEP-32 failed')
        if h[:f] in hashes:
            f += 1
            print(i, h[:f], 'SHA-256 failed')
        keys.add(k[:f])
        hashes.add(h[:f])
        i += 1
    return None, None, 'No duplicates found'

print(findDuplicate())
