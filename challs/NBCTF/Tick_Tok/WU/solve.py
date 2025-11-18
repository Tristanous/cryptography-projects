import socket, json, time, random, statistics

HOST, PORT = "127.0.0.1", 1337

class Conn:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=5)
        self.buf = b""
    def recvline(self):
        while b"\n" not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk: return None
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line
    def timed(self, mac_hex):
        t0 = time.perf_counter()
        self.s.sendall((mac_hex + "\n").encode())
        line = self.recvline()
        dt = time.perf_counter() - t0
        ok, data = False, {}
        if line is not None:
            try:
                data = json.loads(line.decode(errors="ignore"))
                ok = (data.get("status") == "OK")
            except Exception:
                pass
        return dt, ok, data
    def close(self):
        try: self.s.close()
        except: pass

def measure(conn, guess_bytes, n, warm=1):
    h = guess_bytes.hex()
    for _ in range(warm): conn.timed(h)
    a = []
    for _ in range(n):
        dt, _, _ = conn.timed(h); a.append(dt)
    return statistics.median(a)

def main():
    conn = Conn(HOST, PORT)
    try:
        banner = conn.recvline()
        info = json.loads(banner.decode())
        L = int(info["mac_len"])
        conn.timed("00"*L)

        pref = b""
        for _ in range(L):
            suf = b"\x00"*(L-len(pref)-1)
            C = list(range(256)); random.shuffle(C)
            coarse = sorted(((measure(conn, pref+bytes([b])+suf, 2, 0), b) for b in C), reverse=True)[:6]
            best  = max(((measure(conn, pref+bytes([b])+suf, 5, 1), b) for _, b in coarse), key=lambda x: x[0])[1]
            pref += bytes([best])

        mac = pref.hex()
        _, ok, data = conn.timed(mac)
        print(data.get("flag", "KO") if ok else "KO")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
