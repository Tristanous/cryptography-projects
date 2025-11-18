import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

d = 10
p = 2**128 + 51
FLAG = b"NBCTF{???????????}"

aes_key_bytes = os.urandom(16)
a0 = int.from_bytes(aes_key_bytes, 'big')
iv_bytes = os.urandom(16)
a1 = int.from_bytes(iv_bytes, 'big')

c = [0] * (d + 1)
c[0] = a0
c[1] = a1

limite_128_bits = 2**128
for i in range(2, d + 1):
    c[i] = random.randint(0, limite_128_bits - 1)

def evaluate_polynomial(x, coeffs, p):
    res = 0
    for i in range(len(coeffs) - 1, -1, -1):
        res = (res * x + coeffs[i]) % p
    return res

P = []
for x_val in range(1, d + 2):
    y_val = evaluate_polynomial(x_val, c, p)
    P.append((x_val, y_val))

ct = AES.new(aes_key_bytes, AES.MODE_CBC, iv=iv_bytes)
encrypted_flag = ct.encrypt(pad(FLAG, AES.block_size))

print(f"n = {p}")
print(f"P = {P}")
print(f"flag = '{encrypted_flag.hex()}'")


