# SHEP32
#### Series Hashing Encryption Protocol

### results of structure test:

```plaintext
3 4c SHEP32 failed
10 4c2 SHEP32 failed
84 44c8 SHA-256 failed
251 c75d3 SHA-256 failed
721 894a8a SHEP32 failed
8864 95d4361 SHA-256 failed
23815 8e81dfd7 SHA-256 failed
95303 c11eb5e6b SHA-256 failed

When hashing i = 0, and i += 1:
The first 7 digits of SHA-256 repeat after i = 8864, while SHEP32 does not repeat until after i = 38139:
8864 95d4361 SHA-256 failed
38139 484cd1e SHEP32 failed
```
