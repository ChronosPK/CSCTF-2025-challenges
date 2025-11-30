#!/usr/bin/env python3
import re, socket, sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)
HOST, PORT = sys.argv[1], int(sys.argv[2])
CLF = r'^(\d+\.\d+\.\d+\.\d+) - - \[(.+?)\] "([A-Z]+) (/[\^\s]*) HTTP/1\.1" (\d{3}) (\d+)$'
# corrected pattern path part: but above has [^\s]*, adjust: (/[\S]*) ??? easier using r'^(.+?) "([A-Z]+) (/[^\s]*) HTTP/1\.1" (\d{3}) (\d+)$'
CLF = r'^.+? "([A-Z]+) (/[^\s]*) HTTP/1\.1" (\d{3}) (\d+)$'

def main():
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        s.recv(4096)
        s.sendall(b"1\n")
        buf = b""
        while b"Answer:" not in buf:
            buf += s.recv(8192)
        txt = buf.decode()
        block = txt.split("BEGIN\n", 1)[1].split("\nEND", 1)[0]
        total = 0
        for line in block.splitlines():
            m = re.match(CLF, line)
            if not m:
                continue
            method, path, status, size = m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            if method == "GET" and path.startswith("/api/v1/") and status == 200:
                total += size
        s.sendall(f"{total}\n".encode())
        print(s.recv(4096).decode(), end="")

if __name__ == "__main__":
    main()
