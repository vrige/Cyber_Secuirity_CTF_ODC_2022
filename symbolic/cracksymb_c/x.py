import claripy
import angr


# claripy.BVS is used to create a symbolic bitvector, while claripy.BVV is used to create a variable with a fix byte value
# claripy.Concat can take a list, but it needs *
proj = angr.Project("./cracksymb", auto_load_libs=False)

chars = [claripy.BVS('c%d' % i, 8) for i in range(23)] # 22 bytes
input_str = claripy.Concat(*chars +[claripy.BVV(b'}\n')]) # + \n

state = proj.factory.full_init_state(
        args = ["./cracksymb"],
        #add_options = angr.options.unicorn,
  add_options ={angr.options.LAZY_SOLVES},
        stdin = input_str
)

print(chars)

# make sure all chars are printable
for c in chars[5:21]: 
    state.solver.add(c >= 0x20, c <= 0x7e)

# there is an hint in the challenge: the input is flag{...}
state.solver.add(chars[0] == 0x66)  #f
state.solver.add(chars[1] == 0x6C)  #l
state.solver.add(chars[2] == 0x61)  #a
state.solver.add(chars[3] == 0x67)  #g
state.solver.add(chars[4] == 0x7B)  #{
state.solver.add(chars[22] == 0x7D) #}

simgr = proj.factory.simulation_manager(state)

# In the code there were many nested if-else condition. In order to solve it needed to go in all the if and avoid all the else.
# So, i put all the else addresses in to avoid
to_find = [0x4033c2,0x403370]
to_avoid = [0x4033d0,0x403369,0x40317c,0x402f79,0x402d77,0x402b7c,0x40297c,0x402781,0x402576,0x402379,0x402181,0x401f7d,0x401d7a,0x401b6d,0x401978,0x40177f,0x401592,0x40139d,0x4011af,0x400fac,0x400da6,0x400bad,0x4009ac,0x400797]
simgr.explore(find=to_find, avoid=to_avoid) 


if simgr.found:
    found = simgr.found[0]
    print(simgr.found[0].posix.dumps(0)) # dump content of stdin
