from pwn import *

context.log_level = 'error'

r = remote('localhost', 1337)


r.recvuntil(b'decrypt: ')
encrypted_message = r.recvline().strip().decode()
r.recvuntil(b'> ')


ALPHABET_CLIENT = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def get_score(payload):
    r.sendline(f"GUESS {payload}".encode())
    r.recvuntil(b'Score: ')
    score = int(r.recvline().strip().decode().split('/')[0])
    r.recvuntil(b'> ')
    return score

secret_alphabet = list('.' * 25)
base_score = get_score('.' * 25)

for char_to_find in ALPHABET_CLIENT:
    for i in range(25):
        if secret_alphabet[i] == '.':
            current_try_list = list(secret_alphabet)
            current_try_list[i] = char_to_find
            if get_score("".join(current_try_list)) == base_score + 1:
                secret_alphabet[i] = char_to_find
                base_score += 1
                break
secret_alphabet_str = "".join(secret_alphabet)

def decrypt_polybius(ciphertext, alphabet):
    grille = {}
    for index, char in enumerate(alphabet):
        grille[f"{(index // 5) + 1}{(index % 5) + 1}"] = char
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        plaintext += grille.get(ciphertext[i:i+2], '?')
    return plaintext

decrypted_password = decrypt_polybius(encrypted_message, secret_alphabet_str)


r.sendline(f"SUBMIT {decrypted_password}".encode())
response = r.recvline().strip().decode()

final_flag = response.split(':')[-1].strip()

print(f"Alphabet retrouvé : {secret_alphabet_str}")
print(f"Phrase correcte   : {decrypted_password}")
print(f"Flag              : {final_flag}")

r.close()