#!/usr/bin/env python3
import socket, sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)
HOST, PORT = sys.argv[1], int(sys.argv[2])

def main():
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        s.recv(4096)
        s.sendall(b"2\n")
        buf = b""
        while b"Answer:" not in buf:
            chunk = s.recv(4096)
            if not chunk: break
            buf += chunk
        line = buf.decode().split("BYTES: ",1)[1].split("\n",1)[0].strip()
        x = 0
        for b in line.split("-"):
            x ^= int(b, 16)
        s.sendall(f"{x:02x}\n".encode())
        print(s.recv(4096).decode(), end="")

if __name__ == "__main__":
    main()
