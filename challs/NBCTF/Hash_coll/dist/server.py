import sys
import os
import hashlib


BLOCK_SIZE = 8
HASH_SIZE_F = 4
HASH_SIZE_G = 4

IV_F = int.from_bytes(os.urandom(HASH_SIZE_F), 'big')

def compression_f(h_in_int, block_bytes):
    block_int = int.from_bytes(block_bytes, 'big')
    h_out_int = (h_in_int + block_int) & 0xFFFFFFFF
    return h_out_int

def hash_F(message):
    if len(message) % BLOCK_SIZE != 0:
        raise ValueError("Align")
        
    current_h = IV_F
    for i in range(0, len(message), BLOCK_SIZE):
        block = message[i:i+BLOCK_SIZE]
        current_h = compression_f(current_h, block)
        
    return current_h.to_bytes(HASH_SIZE_F, 'big')

def hash_G(message):
    return hashlib.sha256(message).digest()[:HASH_SIZE_G]

def hash_H(message):
    return hash_F(message) + hash_G(message)


def get_pair(h_in_hex):
    try:
        h_in_int = int(h_in_hex, 16)
        b1_int = int.from_bytes(os.urandom(BLOCK_SIZE), 'big')
        b2_int = (b1_int + 0x100000000) & 0xFFFFFFFFFFFFFFFF
        
        if b1_int == b2_int:
            b2_int = (b1_int + 0x100000000) & 0xFFFFFFFFFFFFFFFF

        b1_bytes = b1_int.to_bytes(BLOCK_SIZE, 'big')
        b2_bytes = b2_int.to_bytes(BLOCK_SIZE, 'big')
        
        h_next_1 = compression_f(h_in_int, b1_bytes)
        h_next_2 = compression_f(h_in_int, b2_bytes)
        assert h_next_1 == h_next_2
        
        return b1_bytes.hex(), b2_bytes.hex(), f"{h_next_1:08x}"
    except Exception:
        return None, None, None


def main():
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)

    print(f"IV:{IV_F:08x}")

    for _ in range(20):
        try:
            line = input().strip()
            if not line:
                continue

            if line.upper().startswith("ORACLE:"):
                h_hex = line[7:]
                b1_hex, b2_hex, h_next_hex = get_pair(h_hex)
                if b1_hex:
                    print(f"OK:{b1_hex},{b2_hex},{h_next_hex}")
                else:
                    print("ERR:Format")
            
            elif line.upper().startswith("SUBMIT:"):
                parts = line[7:].split(',')
                if len(parts) != 2:
                    print("ERR:Submit")
                    continue
                
                m1 = bytes.fromhex(parts[0])
                m2 = bytes.fromhex(parts[1])
                
                if len(m1) % BLOCK_SIZE != 0 or len(m2) % BLOCK_SIZE != 0:
                    print("ERR:Align")
                    continue
                    
                if m1 == m2:
                    print("ERR:Diff")
                    continue
                
                if len(m1) == 0 or len(m2) == 0:
                    print("ERR:Empty")
                    continue

                h1 = hash_H(m1)
                h2 = hash_H(m2)
                
                if h1 == h2:
                    print(f"NBCTF{{censure}}")
                    sys.exit(0)
                else:
                    print("ERR:NoColl")
            
            else:
                print("ERR:Cmd")

        except EOFError:
            break
        except Exception:
            print("ERR:Internal")
            break

if __name__ == "__main__":
    main()