from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p = 340282366920938463463374607431768211507
P = [(1, 229936095677720480278441998281923923291), (2, 140011853228186934807990445532583305821), (3, 229816337739639740662958745228315793193), (4, 286394757980753612164042244812410244800), (5, 75158017440729872135164364149082002447), (6, 19315350062096486655580915623758361454), (7, 43734227218550198492404828611077304775), (8, 282953951326397362541007935078738853263), (9, 105492576083007289733816161978829169999), (10, 216212981021720282335013528278115713425), (11, 299887508646632569048189719668400297661)]
flag = '38c5c8b8ad52d956b64f30212d7b3edf2eeee4fe1f1e2c773036086e4a80decb3fe6783e335eaf490fe23e45184a2a0c250b7850bf5fd5b57d912fa83119f6a8bcc0b54ddeb010b4797dc021b0272f0f'

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def solve_linear_system(P, p):
    degree = len(P) - 1
    M = []
    Y = []
    for x, y in P:
        row = [pow(x, i, p) for i in range(degree, -1, -1)]
        M.append(row)
        Y.append(y)
    n = len(Y)
    for i in range(n):
        pivot_row = i
        for j in range(i + 1, n):
            if abs(M[j][i]) > abs(M[pivot_row][i]):
                pivot_row = j
        M[i], M[pivot_row] = M[pivot_row], M[i]
        Y[i], Y[pivot_row] = Y[pivot_row], Y[i]
        inv = mod_inverse(M[i][i], p)
        for j in range(i, n):
            M[i][j] = (M[i][j] * inv) % p
        Y[i] = (Y[i] * inv) % p

        for j in range(n):
            if i != j:
                factor = M[j][i]
                for k in range(i, n):
                    M[j][k] = (M[j][k] - factor * M[i][k]) % p
                Y[j] = (Y[j] - factor * Y[i]) % p
    return Y[::-1]


coefficients = solve_linear_system(P, p)
a0_key_int = coefficients[0]
a1_iv_int = coefficients[1]
key_bytes = a0_key_int.to_bytes(16, 'big')
iv_bytes = a1_iv_int.to_bytes(16, 'big')


encrypted_flag_bytes = bytes.fromhex(flag)
cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
decrypted_padded_flag = cipher.decrypt(encrypted_flag_bytes)


final_flag = unpad(decrypted_padded_flag, AES.block_size)

print(final_flag.decode())
