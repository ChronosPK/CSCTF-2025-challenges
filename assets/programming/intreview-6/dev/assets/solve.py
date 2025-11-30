#!/usr/bin/env python3
import socket, sys, struct

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)
HOST, PORT = sys.argv[1], int(sys.argv[2])

def main():
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        s.recv(4096)
        s.sendall(b"6\n")
        buf = b""
        while b"Answer:" not in buf:
            buf += s.recv(8192)
        hexstr = [L.split("HEX: ",1)[1] for L in buf.decode().splitlines() if L.startswith("HEX: ")][0]
        data = bytes.fromhex(hexstr)
        pos = 0; frags = {}
        while pos < len(data):
            t = data[pos]; l = struct.unpack("!H", data[pos+1:pos+3])[0]; v = data[pos+3:pos+3+l]; pos += 3+l
            if t == 0x42 and len(v) >= 2:
                idx = v[0]; ln = v[1]; frags[idx] = v[2:2+ln]
        out = b"".join(frags[i] for i in sorted(frags))
        s.sendall((out.decode()+"\n").encode())
        print(s.recv(4096).decode(), end="")

if __name__ == "__main__":
    main()
