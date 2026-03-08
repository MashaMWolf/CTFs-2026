# RSA Decipher

## Overview

We are given an RSA ciphertext `c`, a modulus `n`, and a public exponent `e = 18`.

## Analysis

In standard RSA, encryption is `c = m^e mod n`. When `e` is small and the plaintext `m` is short enough that `m^e < n`, the modular reduction never actually takes effect. This means `c = m^e` over the integers, with no modulus involved.

## Solution

Since no modular reduction occurred, we can recover the plaintext by computing the exact integer 18th root of `c`. We use `gmpy2.iroot` for arbitrary-precision integer root extraction and verify that the result is exact. Then we convert the resulting integer back to bytes to get the flag.

```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

m, exact = iroot(c, e)
assert exact
flag = long_to_bytes(int(m))
print(flag.decode())
```
## Conclusion

TL;DR - Don't roll your own crypto.
