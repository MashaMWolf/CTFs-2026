# AES-ECB Byte-at-a-Time Oracle Attack

## Challenge

We are given an encryption oracle that:

1. Accepts arbitrary plaintext input via a POST request.
2. Appends a secret flag to our input.
3. Pads the combined message and encrypts it using AES in ECB mode with a fixed, unknown key.
4. Returns the ciphertext as hex.

We can query the oracle as many times as we want. The goal is to recover the secret flag.

## Background

AES (Advanced Encryption Standard) is a block cipher that operates on 16-byte blocks. ECB (Electronic Codebook) is the simplest mode of operation: each 16-byte block of plaintext is encrypted independently with the same key. This means identical plaintext blocks always produce identical ciphertext blocks, which is the core weakness we exploit here.

## The Attack

This is a well-known attack called the ECB byte-at-a-time (or "chosen plaintext") attack. The idea is straightforward: since we control the beginning of the plaintext and the flag is appended after it, we can carefully choose our input length to isolate one unknown byte of the flag at a time at a block boundary, then brute-force that byte by comparing ciphertext blocks.

### Step 1: Determine the flag length

First, we send an empty input and note the ciphertext length (48 bytes, or 3 blocks). Then we incrementally add bytes to our input until the ciphertext grows to 4 blocks. The point at which it grows tells us exactly how many bytes the flag occupies:

```
flag_length = baseline_ciphertext_length - padding_bytes_that_triggered_growth
```

This gave us a flag length of 40 bytes.

### Step 2: Recover the flag one byte at a time

For each byte at index `i` in the flag (0-indexed), we do the following:

**Choose the right padding length.** We send `15 - (i % 16)` bytes of padding (all `A`s). This positions byte `i` of the flag as the last byte of a 16-byte block in the combined plaintext.

For example, to recover flag byte 0, we send 15 `A`s. The server encrypts:

```
Block 0: [A A A A A A A A A A A A A A A ?]
```

where `?` is the first byte of the flag. We record the ciphertext of block 0.

**Brute-force the unknown byte.** We then send 15 `A`s followed by a candidate character `c` and check if block 0 of the resulting ciphertext matches our target. When it matches, we know `c` equals the first flag byte. Because ECB encrypts each block independently, identical plaintext blocks always produce identical ciphertext blocks, so the comparison is reliable.

**Repeat.** Once we know byte 0, we recover byte 1 by sending 14 `A`s (so the first block is `AAAAAAAAAAAAAA` + flag[0] + flag[1]) and brute-forcing the last position again. We continue this process across block boundaries until the entire flag is recovered.

The key calculation for each byte `i`:

- **Padding length:** `15 - (i % 16)`
- **Block to compare:** `i // 16`

### Step 3: Skip the known prefix

We knew the flag format was `TACHYON{...}`, so we started brute-forcing from byte 8 onward, saving a few hundred oracle queries.

## Solution Script

```python
import requests
import string

URL = "https://aes-challenge-thingy.vercel.app/api/oracle"
BLOCK_SIZE = 16
CHARSET = string.printable.strip()

def encrypt(plaintext: str) -> bytes:
    resp = requests.post(URL, json={"input": plaintext})
    return bytes.fromhex(resp.json()["ciphertext"])

def get_block(ct: bytes, block_num: int) -> bytes:
    return ct[block_num * BLOCK_SIZE:(block_num + 1) * BLOCK_SIZE]

# Step 1: Find flag length
baseline_len = len(encrypt(""))

for i in range(1, BLOCK_SIZE + 1):
    if len(encrypt("A" * i)) > baseline_len:
        flag_len = baseline_len - i
        print(f"Flag length: {flag_len} bytes")
        break

# Step 2: Recover flag byte by byte
known = "TACHYON{"
for i in range(len(known), flag_len):
    block_num = i // BLOCK_SIZE
    pad_len = BLOCK_SIZE - 1 - (i % BLOCK_SIZE)
    padding = "A" * pad_len

    target_block = get_block(encrypt(padding), block_num)

    for c in CHARSET:
        test = padding + known + c
        if get_block(encrypt(test), block_num) == target_block:
            known += c
            print(f"[{i+1}/{flag_len}] {known}")
            break

print(f"\nFlag: {known}")
```

## Flag

```
TACHYON{w3lp_3cp_1s_bu5t3ed_L0l_d23d3cf}
```

## Conclusion

ECB mode is fundamentally broken for any use case where an attacker has influence over part of the plaintext. The fact that identical blocks encrypt to identical ciphertext makes it trivial to extract secrets byte by byte. This is why ECB is almost never used in practice. Modes like CBC, CTR, or GCM introduce randomness (via IVs or nonces) that prevent this class of attack entirely. TL;DR - Don't roll your own crypto.
