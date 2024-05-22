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

The level of randomness in a hashing algorithm can be assessed by how uniformly it distributes its outputs and how long it takes before a collision (a duplicate output) occurs. When considering which hashing algorithm appears to exhibit more randomness based on the number of attempts before a collision occurs, the algorithm where a collision occurs after 30,000 attempts would generally be considered more random compared to one where a collision occurs after 9,000 attempts.


This assessment is based on the idea that a more random hashing algorithm would spread its outputs more evenly across all possible hash values before any collision is likely. Therefore, the higher the number of attempts needed to find a duplicate, the better the hashing function is at distributing its hash values uniformly.


For more precision in this analysis, one could look into the theoretical collision probabilities based on hash length and the number of hash operations performed. For example, using the Birthday Paradox principles, one can calculate expected collision occurrences to evaluate the algorithm's effectiveness more rigorously. However, with the information provided, the algorithm with collisions occurring later (after 30,000 hashes) shows more effective randomness.
