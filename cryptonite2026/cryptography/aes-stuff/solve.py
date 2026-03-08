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
print(f"Baseline: {baseline_len} bytes ({baseline_len // BLOCK_SIZE} blocks)")

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

    found = False
    for c in CHARSET:
        test = padding + known + c
        if get_block(encrypt(test), block_num) == target_block:
            known += c
            print(f"[{i+1}/{flag_len}] {known}")
            found = True
            break

    if not found:
        print(f"Could not find byte {i+1}, stopping.")
        break

print(f"\nFlag: {known}")
