from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#r = process("./keycheck_baby", aslr = False) #
r = remote("bin.training.offdef.it", 4101)

'''
gdb.attach(r, """
	brva 0x13b7 
	start
	c
""")
'''

# First of all, modify the binary to remove all the sleeps or at least decrease the time
# local = "babuzzbabuzzb"
local_hex = b"\x62\x61\x62\x75\x7A\x7A\x62\x61\x62\x75\x7A\x7A\x62"
magic0    = b"\x1b\x51\x17\x2a\x1e\x4e\x3d\x10\x17\x46\x49\x14\x3d"
magic1 	  = b"\xeb\x51\xb0\x13\x85\xb9\x1c\x87\xb8\x26\x8d\x07"

binary_local_hex = local_hex.decode("ascii") 
binary_magic0 = magic0.decode("ascii")  

print(binary_local_hex)
print(binary_magic0)

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

xored = xor_strings(binary_local_hex, binary_magic0)#.encode("hex")
print(xored)

'''
      a = -69;
      for (i = 0; i< 12; i++) {
        a = a + input2[i]
        if (a != magic1[i]) goto LAB_00101487;
      }
'''
a = -69
input2 = []
second = b""
# I computed the first without the python
for i in range(1,12):

	b = ord(magic1[i]) - ord(magic1[i-1])
	if b < 0:
		b = b + 256
	c = hex(b)
	input2.append(c)
	#print("b: " + str(b) + " , c: " + str(c) + " , char: " + chr(b))
	second = second + chr(b)


something = xored + "0" + second

reversing = b"flag{" + something + b"}"
print(reversing)
# flag{y0u_d4_qu33n_0f_cr4ck1ngz}
r.send(reversing)

r.interactive()

input("ls")
