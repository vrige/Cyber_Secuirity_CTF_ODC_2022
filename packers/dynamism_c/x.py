'''
It was a problem to rewrite the unpacked function on the binary, so unpacked it in a empty binary, but it was messy.
However, the unpacking works in this way:
- it downloads everything from internet, then it executes it and finally the unpacked code is removed
The unpacking function is called three times and download three different codes:
- the first one saves something in the heap -> nine address of 8 bytes each (the first one is the seed and the rest is the flag)
- the second encrypt the input with the seed and saves it in the heap (notice that it requires the input to be 8 bytes long)
- Finally, a check between the input and the output
The challenge can be completely analyzed in dynamic

gdb --args ./dynamism $(perl -e 'print "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHH"')

useful breakpoints:
brva 0x11f1   main (before unpacking)
brva 0x1569   unpacking
brva 0x1574

Dumping memory instructions:
dump binary memory first.bin $rax ($rax + 8 * 0x74)
dump binary memory first.bin_1 $rax ($rax + 8 * 0x38)
dump binary memory first.bin_2 $rax ($rax + 8 * 0x46)



f = open("./reverse","rb")
old = f.read()
f.close()
f = open("./first.bin_1","rb")
first = f.read()
f.close()
f = open("./first.bin_2","rb")
second = f.read()
f.close()

base_offset = 0x5fa
len_ = 0x38
instr_len = 8

new = old[:base_offset] + first + old[base_offset + (len_ * instr_len):]

f = open("./dynamism_2","wb")
f.write(new)
f.close()

base_offset = 0x5fa
len_ = 0x46
instr_len = 8

new = old[:base_offset] + second + old[base_offset + (len_ * instr_len):]

f = open("./dynamism_3","wb")
f.write(new)
f.close()


# results in the heap from the first routine
0x55555555b2a0:	0x4827c3baaa35c7cc	0x2648a0c1cd54abaa
0x55555555b2b0:	0x3c46afcfde54b5ab	0x3178e2e5d05ba8a5
0x55555555b2c0:	0x3c78b7d5cd6ab2a3	0x1740a2d6cc6aa2a4
0x55555555b2d0:	0x265ea7e5c75ab5aa	0x3c4e9cc9cb4298ed
0x55555555b2e0:	0x35189cded854af93	0x0000000000000000

# results in the heap from the second routine (after xor)
# notice that only the first "address" (0x4827c3baaa35c7cc)is used in the xor as seed
0x55555555b3a0:	0x096682fbeb74868d	0x0a6581f8e877858e
0x55555555b3b0:	0x0b6480f9e976848f	0x0c6387feee71838f
0x55555555b3c0:	0x046880e5f979c788	0x781ab0c897669583
0x55555555b3d0:	0x7b1cf28a975ca3f6	0x7316f387c459fdf8

When you understand that that the input is xored with the first address received, then you can stop analyzing it and just reverse it
'''
from pwn import * 
seed = 0x4827c3baaa35c7cc
arg = [0x2648a0c1cd54abaa,0x3c46afcfde54b5ab,0x3178e2e5d05ba8a5,0x3c78b7d5cd6ab2a3,0x1740a2d6cc6aa2a4,0x265ea7e5c75ab5aa,0x3c4e9cc9cb4298ed,0x35189cded854af93]
output = []

for i in range(len(arg)):
    arg[i] = hex(seed ^ arg[i])
    #output.append(seed ^ arg[i])
    print(arg[i])


# you need to take the result of the xor, invert them (from big_endian to little endian) and convert from hex tro ascii
# i did the last two parts online

#flag{congratulationz_!_you_got_the_flag_from_dyn!_was_it_hard_?}



