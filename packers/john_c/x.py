import claripy
import angr
import angrcli.plugins.ContextView
from angrcli.interaction.explore import ExploreInteractive

# to pass the input to gdb you need to use:
# gdb --args ./john $(perl -e 'print "flag{packer-AAAAAAAA&-annoying__}"')
'''
after dumping the memory, we can see that there are many checks on the input:
- it should start with "flag{"
- it should end with "}"
- it should be printable
- it should be long 33 chars
- and other three checks on first, midlle and last part
Notice that the reversing on the first part is quite easy, because you can discorver it by looking with gdb on the check.
While the last part can be solved with a z3 solver and reversing the algorithm extraced from ghidra, by printing everything and checking which input make sense.
The central part is the most difficult part, but given all the other part, it may be found with an angr solver.
'''
# the following breakpoints amy very useful:
# b*0x0804928a   for the routine
# b*0x08049683   for the central check 
# b*0x0804965b 
# flag{packer-4r3-1337&-annoying__}
'''
# claripy.BVS is used to create a symbolic bitvector, while claripy.BVV is used to create a variable with a fix byte value
# claripy.Concat can take a list, but it needs *
proj = angr.Project("./john", auto_load_libs=False)

chars = [claripy.BVS('c%d' % i, 8) for i in range(33)] # 
input_str = claripy.Concat(*chars +[claripy.BVV(b'\n')]) # + \n

state = proj.factory.full_init_state(
        args = ["./john"],
        #add_options = angr.options.unicorn,
  	add_options ={angr.options.LAZY_SOLVES,angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY},
        stdin = input_str
)

print(chars)

# make sure all chars are printable
for c in chars: 
    state.solver.add(c >= 0x20, c <= 0x7e)

# there is an hint in the challenge: the input is flag{...}
state.solver.add(chars[0] == 0x66)  #f
state.solver.add(chars[1] == 0x6C)  #l
state.solver.add(chars[2] == 0x61)  #a
state.solver.add(chars[3] == 0x67)  #g
state.solver.add(chars[4] == 0x7B)  #{
state.solver.add(chars[5] == 0x70)  #p
state.solver.add(chars[6] == 0x61)  #a
state.solver.add(chars[7] == 0x63)  #c
state.solver.add(chars[8] == 0x6b)  #k
state.solver.add(chars[9] == 0x65)  #e
state.solver.add(chars[10] == 0x72) #r
state.solver.add(chars[11] == 0x2d) #-    this was a guess
state.solver.add(chars[12] == 0x34) #4    this was a guess (thanks to the rest of the flag)
state.solver.add(chars[13] == 0x72) #r
state.solver.add(chars[14] == 0x33) #3
state.solver.add(chars[15] == 0x2d) #-

state.solver.add(chars[20] == 0x26) #&
state.solver.add(chars[21] == 0x2d) #-
state.solver.add(chars[22] == 0x61) #a
state.solver.add(chars[23] == 0x6e) #n
state.solver.add(chars[24] == 0x6e) #n
state.solver.add(chars[25] == 0x6f) #o
state.solver.add(chars[26] == 0x79) #y
state.solver.add(chars[27] == 0x69) #i
state.solver.add(chars[28] == 0x6e) #n
state.solver.add(chars[29] == 0x67) #g
state.solver.add(chars[30] == 0x5f) #_
state.solver.add(chars[31] == 0x5f) #_
state.solver.add(chars[32] == 0x7d) #}


simgr = proj.factory.simulation_manager(state)


to_find = [0x0804983e]
to_avoid = [0x08049850]
simgr.explore(find=to_find, avoid=to_avoid)

# state.explore() basically just does the following on each call
#e = ExploreInteractive(proj, state)
#e.cmdloop()

print(simgr)
if simgr.found:
    found = simgr.found[0]
    print(simgr.found[0].posix.dumps(0)) # dump content of stdin
    


# breakpoint for checking 6 chars after flag{
# b* 0x80496ed
# on theregister  eax there is the correct char, while on ebx there is the input
# flag{packer-AAAAAAAA&-annoying__}

'''

'''
# this is some code from ghidra to get the check on the last chars 
# we want to get the algorithm that it is using 
EDX = iter = 0
EAX = 0x804a081
EAX = 0x804a081 + iter = 0x804a081
ECX = key[iter] = 0xb
                           Compute the address of DAT_0804a081                             
        08049575 8b 55 1c        MOV        EDX,dword ptr [EBP + index]
        08049578 8b 45 f4        MOV        EAX,dword ptr [EBP + local_10]
        0804957b 01 d0           ADD        EAX,EDX
        0804957d 0f b6 08        MOVZX      ECX,byte ptr [EAX]=>DAT_0804a081
   
eax = iter = 0
edx = 0x14 (number of previous chars)
eax = input[iter] = 0x70
			   compute the char of the input(iter)              		   
        08049580 8b 45 1c        MOV        EAX,dword ptr [EBP + index]
        08049583 8d 50 14        LEA        EDX,[EAX + 0x14]
        08049586 8b 45 18        MOV        EAX,dword ptr [EBP + Stack[0x14]]
        08049589 01 d0           ADD        EAX,EDX
        0804958b 0f b6 00        MOVZX      EAX,byte ptr [EAX]

eax = eax ^ ecx = input[iter] ^ key[iter] = 0x7b
			   annoying operation
        0804958e 31 c8           XOR        EAX,ECX

			   save result
        08049590 88 45 f2        MOV        byte ptr [EBP + local_12],AL

eax = iter = 0
eax = eax + edx = 0x15 = input(iter+1) 
        08049593 8b 45 1c        MOV        EAX,dword ptr [EBP + index]
        08049596 83 c0 15        ADD        EAX,0x15
        08049599 89 c2           MOV        EDX,EAX
        0804959b 8b 45 18        MOV        EAX,dword ptr [EBP + Stack[0x14]]
        0804959e 01 d0           ADD        EAX,EDX
        080495a0 0f b6 00        MOVZX      EAX,byte ptr [EAX]

			save result
        080495a3 88 45 f3        MOV        byte ptr [EBP + local_11],AL

eax = 0x7b			
			load prvious result
        080495a6 0f b6 45 f2     MOVZX      EAX,byte ptr [EBP + local_12]

        080495aa 3a 45 f3        CMP        AL,byte ptr [EBP + local_11]
        080495ad 74 07           JZ         LAB_080495b6

# The algorithm is: input[iter+1] = input[iter] ^ key[iter]
# on the following lines there is the solver to find just 12 chars on the last check (before "}")
# many output, but the only one that makes sense is:
# &-annoying__
'''

from z3 import *
key=[0x0b, 0x4c, 0x0f, 0x00, 0x01, 0x16, 0x10, 0x07, 0x09, 0x38,0x00]
models =[]
range_min = 33
range_max = 80
for i in range(range_min,range_max,1):
    s=z3.Solver()
    input_ = [BitVec("input%s" % i, 8) for i in range(len(key)+1)]
    for m in range(len(key)): 
        s.add(input_[m+1] == input_[m] ^ key[m])
        s.add(input_[m] <= 0x7d)
        s.add(input_[m] >= 0x21)
    s.add(input_[len(key)] <= 0x7d)
    s.add(input_[len(key)] >= 0x21)
    s.add(input_[0] == i)
    s.check()
    print("model " + str(i))
    print(s.check())
    if s.check() == z3.sat:
        model = s.model()
        models.append(model)
        [print(chr(int(str(model.eval(input_[j]))))) for j in range(len(key)+1)]
    else:
        models.append(None)
        print("No good")
    print("\n")

