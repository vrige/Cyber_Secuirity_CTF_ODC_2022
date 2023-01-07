## Challange
Inject a shellcode with a stack canary and without a global variable.
## Solution
Similar to the first mitigation challange, but now there is no global variable to write the shellcode. In this case we can exploit the stack to execute the shellcode, but we have to leak the stack address.
1. In the first loop iteration we leak the canary as previously.
2. In the second loop we leak the stack address, which in this case is `4*8` bytes after the canary. Since the address stored in that position is always `0x158` times less then the start of our shellcode we can leak the stack address value and subtract `0x158`.
3. In the third iteration we send the shellcode and `\x90` until 104 characters, the canary, random stuff for `EBP` and the value calcuted at point 2.
