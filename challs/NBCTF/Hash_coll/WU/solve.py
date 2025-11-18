from pwn import *
import hashlib

context.log_level = 'error'

HOST = 'localhost'
PORT = 1337

HASH_SIZE_G_BYTES = 4

def hash_G(message):
    return hashlib.sha256(message).digest()[:HASH_SIZE_G_BYTES]

def solve():
    conn = remote(HOST, PORT)

    iv_line = conn.recvline().decode().strip()
    if not iv_line.startswith("IV:"):
        conn.close()
        return
    
    initial_iv_hex = iv_line[3:]

    t = 16
    colliding_blocks_pairs = []
    current_h = initial_iv_hex
    
    for i in range(t):
        conn.sendline(f"ORACLE:{current_h}".encode())
        response = conn.recvline().decode().strip()
        
        if not response.startswith("OK:"):
            conn.close()
            return

        parts = response[3:].split(',')
        b1 = bytes.fromhex(parts[0])
        b2 = bytes.fromhex(parts[1])
        current_h = parts[2]
        
        colliding_blocks_pairs.append((b1, b2))

    g_hashes = {}

    for i in range(2**t):
        message_blocks = []
        for j in range(t):
            if (i >> j) & 1:
                message_blocks.append(colliding_blocks_pairs[j][1])
            else:
                message_blocks.append(colliding_blocks_pairs[j][0])
        
        message = b"".join(message_blocks)
        
        g_hash = hash_G(message)
        
        if g_hash in g_hashes:
            m1 = g_hashes[g_hash]
            m2 = message
            
            if m1 != m2:
                conn.sendline(f"SUBMIT:{m1.hex()},{m2.hex()}".encode())
                
                flag_line = conn.recvline_contains(b"FLAG{").decode().strip()
                print(flag_line)
                
                conn.close()
                return
        else:
            g_hashes[g_hash] = message
            
    conn.close()

if __name__ == "__main__":
    solve()