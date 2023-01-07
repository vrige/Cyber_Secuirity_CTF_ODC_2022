## Challange
Inject a shellcode with a stack canary.
## Solution
Since there is a canary stack protection we might leak the canary or don't overwrite it. Given the variable position in stack the second option is not viable.
In order to leak the canary we need some way to print it out. In our case there is buffer which is printed. Since is next to the canary if we overwrite all the 104 bytes plus 1 (the plus 1 is needed to overwrite the `\x00` least byte of the canary) the printf will also print the 7 bytes of the canary.
With the canary we can overwrite the EIP without triggering the final check. So the steps to spawn the shell are:
1. On `ps1` input the shellcode, the variable is on the `.bss` so the address is fixed. We will jump to this.
    ```assembly
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
    ```
2. On buffer, input first the 105 bytes of random stuff to get the canary using `r.recv`. Then on the second loop iteration inject 104 bytes, the canary and the address of the shellcode.


