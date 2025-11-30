#!/usr/bin/env python3
import socket, sys, hmac, hashlib

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)
HOST, PORT = sys.argv[1], int(sys.argv[2])

def main():
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        s.recv(4096)
        s.sendall(b"4\n")
        buf = b""
        while b"Answer:" not in buf:
            buf += s.recv(4096)
        line = [L for L in buf.decode().splitlines() if L.startswith("key=")][0]
        kv = dict(p.split("=",1) for p in line.split())
        mac = hmac.new(kv["key"].encode(), (kv["token"]+kv["salt"]).encode(), hashlib.sha256).hexdigest()
        s.sendall((mac+"\n").encode())
        print(s.recv(4096).decode(), end="")

if __name__ == "__main__":
    main()
