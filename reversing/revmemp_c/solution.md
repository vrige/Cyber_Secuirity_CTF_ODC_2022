## Challange
Find the flag stored in the program memory, there are mitigations agains the usage of gdb (ptrace and int checks).
## Solution
There are two solutions:
- After using ghidra to find the addresses of exit function and compare, modify the hex to be nop and always set the compare to true.
- Create a fake library using the command `gcc -fPIC libfacek.c -o libefake.so -shared` which implements the function `strncmp` found using ghidra to print the input string (the flag).
- Load the library and executes the binary using `LD_PRELOAD=./libfake.so ./revmem asdasd`
