from pwn import *
import time

p = process("./chall")
#p = remote("pwn.challenge.bi0s.in", 1234)

gdb.attach(p)

p.interactive()
