def substrings(k):
    return [k[:i] for i in range(1, 9)]

i = 2
results, seen, found = [], set(), False
seen = set()
occurrences = {}

while True:
    i += 1
    n = fetchKey(i)
    print(n, i)
    if n in seen: found = True; break
    strings = [n[:i] for i in range(1, 9)]
    seen.update(strings)
    if i % 1000 == 0:
        for s in strings:
            occurrences[s] = occurrences.get(s, 0) + 1
# for v, c in counts: print(f"{v}: {c}")
