## Challange
Using ROP spawn a shellcode but you can write 4 bytes and 4 bytes, statically linked (no one gadget for `bin/sh`, lib functions directly in the file).
## Solution
The first step is to get the rop gadgets addresses. Since the file is statically linked and there is no PIE, we can get by using ROPgadget(also the online tool for syscall ret) from binary easyrop.
We have a gadget to pop the argument for exec and one for doing syscall, but we need the pointer to `/bin/sh`. 
Since in the file there is no `/bin/sh` reference, we use the same gadget to pop the argument for a read and write on the global variable len the string `/bin/sh`. Then, we will use the pointer to len as argument for the second gadget.
In order the gadgets are:
```
Fill 14 rounds
ptr_gadget
read arguments to be popped
ptr_syscall
argument 0 because there is a pop rbp
ptr_gadget
execve arguments to be popped
ptr_syscall
exit from loop
send string /bin/sh
```
