#!/usr/bin/env python3
import socket, sys, hmac, hashlib, base64

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)
HOST, PORT = sys.argv[1], int(sys.argv[2])

def b64url_no_pad(b:bytes)->str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def main():
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        s.recv(4096)
        s.sendall(b"5\n")
        buf = b""
        while b"Answer" not in buf:
            buf += s.recv(8192)
        txt = buf.decode().splitlines()
        secret = next(L.split("=",1)[1] for L in txt if L.startswith("secret="))
        header = next(L.split("=",1)[1] for L in txt if L.startswith("header="))
        payload = next(L.split("=",1)[1] for L in txt if L.startswith("payload="))
        sig = b64url_no_pad(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
        s.sendall((sig+"\n").encode())
        print(s.recv(4096).decode(), end="")

if __name__ == "__main__":
    main()
