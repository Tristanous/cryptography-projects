from __future__ import annotations
import os, hmac, hashlib, json, secrets, select, sys

FLAG = "NBCTF{comme_quoi_c_est_beaucoup_3_milliemes}"

KNOWN_MESSAGE = f"CestVraimentSuperLeNBCTF_SurtoutLaCrypto"
SECRET_KEY = os.urandom(32)
CORRECT_MAC = hmac.new(SECRET_KEY, KNOWN_MESSAGE.encode(), hashlib.sha1).digest()[:12]

def timing_compare(user_mac: bytes, correct_mac: bytes) -> bool:
    if len(user_mac) != len(correct_mac):
        return False
    for i in range(len(correct_mac)):
        if user_mac[i] != correct_mac[i]:
            return False
        select.select([], [], [], len(b"\0\0\0")/1000)
    return True

def handle_client(_conn=None):
    info = {"message": KNOWN_MESSAGE, "mac_len": 12}
    sys.stdout.write(json.dumps(info, separators=(",",":")) + "\n"); sys.stdout.flush()
    try:
        while True:
            line = sys.stdin.readline()
            if line == "":
                return
            mac_hex = line.strip()
            if not mac_hex:
                continue
            try:
                user_mac = bytes.fromhex(mac_hex)
            except ValueError:
                sys.stdout.write('{"error":"bad_hex"}\n'); sys.stdout.flush()
                continue
            if len(user_mac) != 12:
                sys.stdout.write('{"error":"bad_len"}\n'); sys.stdout.flush()
                continue
            if timing_compare(user_mac, CORRECT_MAC):
                sys.stdout.write(json.dumps({"status":"OK","flag":FLAG}) + "\n"); sys.stdout.flush()
            else:
                sys.stdout.write('{"status":"Failed"}\n'); sys.stdout.flush()
    finally:
        pass 
def main():
    handle_client(None)

if __name__ == "__main__":
    main()
