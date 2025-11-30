#!/usr/bin/env python3
import socket, sys, base64

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)
HOST, PORT = sys.argv[1], int(sys.argv[2])

def main():
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        s.recv(4096)
        s.sendall(b"3\n")
        buf = b""
        while b"Answer:" not in buf:
            buf += s.recv(8192)
        lines = buf.decode().split("BEGIN\n",1)[1].split("\nEND",1)[0].strip().splitlines()
        parts = []
        for L in lines:
            idx, b64 = L.split(":",1)
            i,_N = map(int, idx.split("/"))
            parts.append((i, b64))
        parts.sort(key=lambda t:t[0])
        msg = b"".join(base64.b64decode(b, validate=False) for _, b in parts).decode()
        s.sendall((msg+"\n").encode())
        print(s.recv(4096).decode(), end="")

if __name__ == "__main__":
    main()
