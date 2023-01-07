import claripy
import angr

# I used angr + claripy to solve this challenge
# I created 30 symbolic variables and I costrained them to be printable chars (I avoided white spaces)
# then to close the challenge I just sent the result without the local implemntation
'''
proj = angr.Project("./prodkey")

chars = [claripy.BVS('c%d' % i, 8) for i in range(30)] # 30 bytes
input_str = claripy.Concat(*chars + [claripy.BVV(b'\n')]) # + \n
initial_state = proj.factory.entry_state(stdin=input_str) # use as stdin
for c in chars: # make sure all chars are printable
    initial_state.solver.add(c >= 0x21, c <= 0x7e)
simgr = proj.factory.simulation_manager(initial_state)

# this addresses are from ghidra and they correspond to the value returned by the function that checks the input
to_find = [0x400deb]
to_avoid = [0x400df2]
simgr.explore(find=to_find, avoid=to_avoid) #

if simgr.found:
    found = simgr.found[0]
    print(simgr.found[0].posix.dumps(0)) # dump content of stdin

   
#b'M4@@9-8@@7@-@@@9@-6@BB2-@@@88!\n'
'''

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
r = remote("bin.training.jinblack.it", 2021)
payload = b"M4@@9-8@@7@-@@@9@-6@BB2-@@@88!\n"
r.send(payload)
r.interactive()
