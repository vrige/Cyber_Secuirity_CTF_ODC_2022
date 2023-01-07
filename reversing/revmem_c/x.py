import claripy
import angr

proj = angr.Project("./revmem")

argv = ['./revmem']
argv.append(claripy.BVS('arg1', 30*8)) # symbolic first argument

state = proj.factory.entry_state(args=argv)
simgr = proj.factory.simulation_manager(state)

simgr.explore(find=0x400000+0x1236, avoid=0x400000+0x1244) # explore...

if simgr.found:
    found = simgr.found[0]
    print(found.solver.eval(argv[1]).to_bytes(30, 'big'))
    #import IPython
    #IPython.embed()
    # print(found.solver.eval(argv[1]).to_bytes(30, 'big')) # eval