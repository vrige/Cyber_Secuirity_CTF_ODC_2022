'''
# the original file is john, but I am going to modify it multiple times with the unpacked code.
# in the following section I stored some useful data for dumping the memory
# I decided to do it in multiple shots, because I wasn't sure about nested calls

# this 0x0804928a is the address of the calling rountine 

base_address = 0x08048000
list of borders and offsets with the base_address of the binary:
- 0x0804970e    off = 0x170e    len = 0x53     instr_len = 4     address_for_dumping = 0x0804970e
	dump binary memory first.bin $eax ($eax + 4 * 0x53)
	john_patched

- 0x080492a0    off = 0x12a0    len = 0x11     instr_len = 4     address_for_dumping = 0x080492a0
	dump binary memory first.bin_1 $eax ($eax + 4 * 0x11)
- 0x080492e5    off = 0x12e5    len = 0x11     instr_len = 4	 address_for_dumping = 0x080492e5
	dump binary memory first.bin_2 $eax ($eax + 4 * 0x11)
- 0x08049329    off = 0x1329    len = 0x17     instr_len = 4     address_for_dumping = 0x08049329
	dump binary memory first.bin_3 $eax ($eax + 4 * 0x17)
- 0x080496ab    off = 0x16ab    len = 0x18     instr_len = 4     address_for_dumping = 0x080496ab
	dump binary memory first.bin_4 $eax ($eax + 4 * 0x18)
	john_patched_1
	notice that the following routine is inside the previous one, so you need to unpatch here

- 0x08049385    off = 0x1385    len = 0x36     instr_len = 4     address_for_dumping = 0x08049385
	dump binary memory first.bin_5 $eax ($eax + 4 * 0x36)
- 0x080495e4    off = 0x15e4    len = 0x31     instr_len = 4	 address_for_dumping = 0x080495e4
	dump binary memory first.bin_6 $eax ($eax + 4 * 0x31)
	john_patched_2

- 0x0804945e    off = 0x145e    len = 0x30     instr_len = 4	 address_for_dumping = 0x0804945e
	dump binary memory first.bin_7 $eax ($eax + 4 * 0x30)
- 0x08049546    off = 0x1546    len = 0x27     instr_len = 4
	dump binary memory first.bin_8 $eax ($eax + 4 * 0x27)
- 0x0804951f    off = 0x151f    len = 0x9      instr_len = 4
	dump binary memory first.bin_9 $eax ($eax + 4 * 0x9)
	john_patched_3

We need to dump the memory for each file (i will keep them separated)

'''

'''
f = open("./john","rb")
old = f.read()
f.close()
f = open("./first.bin","rb")
first = f.read()
f.close()

base_offset = 0x170e
len_ = 0x53
instr_len = 4

new = old[:base_offset] + first + old[base_offset + (len_ * instr_len):]

f = open("./john_patched","wb")
f.write(new)
f.close()
'''

'''
f = open("./john_patched","rb")
old = f.read()
f.close()

f = open("./first.bin_1","rb")
first = f.read()
f.close()
f = open("./first.bin_2","rb")
second = f.read()
f.close()
f = open("./first.bin_3","rb")
third = f.read()
f.close()
f = open("./first.bin_4","rb")
forth = f.read()
f.close()

base_offset = 0x12a0
len_ = 0x11
instr_len = 4

new = old[:base_offset] + first + old[base_offset + (len_ * instr_len):]

base_offset = 0x12e5
len_ = 0x11
instr_len = 4

new = new[:base_offset] + second + new[base_offset + (len_ * instr_len):]

base_offset = 0x1329
len_ = 0x17
instr_len = 4

new = new[:base_offset] + third + new[base_offset + (len_ * instr_len):]

base_offset = 0x16ab
len_ = 0x18
instr_len = 4

new = new[:base_offset] + forth + new[base_offset + (len_ * instr_len):]

f = open("./john_patched_1","wb")
f.write(new)
f.close()
'''

'''
f = open("./john_patched_1","rb")
old = f.read()
f.close()

f = open("./first.bin_5","rb")
first = f.read()
f.close()
f = open("./first.bin_6","rb")
second = f.read()
f.close()

base_offset = 0x1385
len_ = 0x36
instr_len = 4

new = old[:base_offset] + first + old[base_offset + (len_ * instr_len):]

base_offset = 0x15e4
len_ = 0x31
instr_len = 4

new = new[:base_offset] + second + new[base_offset + (len_ * instr_len):]

f = open("./john_patched_2","wb")
f.write(new)
f.close()
'''

'''
f = open("./john_patched_2","rb")
old = f.read()
f.close()

f = open("./first.bin_7","rb")
first = f.read()
f.close()
f = open("./first.bin_8","rb")
second = f.read()
f.close()
f = open("./first.bin_9","rb")
third = f.read()
f.close()

base_offset = 0x145e
len_ = 0x30
instr_len = 4

new = old[:base_offset] + first + old[base_offset + (len_ * instr_len):]

base_offset = 0x1546
len_ = 0x27
instr_len = 4

new = new[:base_offset] + second + new[base_offset + (len_ * instr_len):]
base_offset = 0x151f
len_ = 0x9
instr_len = 4

new = new[:base_offset] + third + new[base_offset + (len_ * instr_len):]

f = open("./john_patched_3","wb")
f.write(new)
f.close()
'''
