import claripy

# the first thing to do is to copy paste python-like the algorithm and check if it works without using any solver.
# it must return a print similar to the one of the binary.
# Notice that it's not exactly the same as the one in c. The main are two main differences:
# - i added " & 0xffffffff" to m_sendRand because C works with memory while python with arrays
# - mag.3808 global variable is substitued with if-else (notice that (uint)state[index + 1] & 1 can assume only two possibile values: 0 and 1)
# - python arguments of functions are apssed by copy and not reference (so the return is necessary)
# you can check that final1 = 0x6c31f24d when the seed is seed = 0x4c8ea3e8
# After checking all this, you can add claripy and solve it

import claripy

MAG = [claripy.BVV(0x0, 32), claripy.BVV(0x9908b0df, 32)]

def mag(content):
	return claripy.If(content == 0, MAG[0], MAG[1])

def genRandLong(state):  
	if ((0x26f < state[0x270]) or (state[0x270] < 0)): # no claripy.Or(), it says values might be symbolic
		if ((0x270 < state[0x270]) or (state[0x270] < 0)): # no claripy.Or(), it says values might be symbolic
			state = m_seedRand(state,0x1105)
		for index in range(0xe3): # divide the arguments of the xor to bitwise-and them with 0xfffffffff to have "args with same lenght"
			arg1 = state[index + 0x18d] & 0xffffffff
			arg2 = (claripy.LShR((state[index + 1] & 0x7fffffff | state[index] & 0x80000000), 1)) & 0xffffffff
			arg3 = mag(state[index + 1] & 1)& 0xffffffff
			state[index] =  arg1 ^ arg2 ^  arg3
		for index in range(0xe3,0x26f): 
			arg1 = state[index - 0xe3] & 0xffffffff
			arg2 = (claripy.LShR((state[index + 1] & 0x7fffffff | state[index] & 0x80000000), 1)) & 0xffffffff
			arg3 = mag(state[index + 1] & 1) & 0xffffffff
			state[index] = arg1 ^ arg2 ^  arg3
		arg1 = state[0x18c] & 0xffffffff
		arg2 = (claripy.LShR((state[0] & 0x7fffffff | state[0x26f] & 0x80000000), 1)) & 0xffffffff
		arg3 = mag(state[0] & 1) & 0xffffffff
		state[0x26f] = arg1 ^ arg2 ^  arg3
		state[0x270] = 0 & 0xffffffff

	iVar1 = (state[0x270]) & 0xffffffff
	state[0x270] = (iVar1 + 1) & 0xffffffff
	uVar2 = (state[iVar1] ^ claripy.LShR(state[iVar1], 0xb) ) & 0xffffffff
	uVar2 = (uVar2 ^ (uVar2 << 7) & 0x9d2c5680) & 0xffffffff
	uVar2 = (uVar2 ^ (uVar2 << 0xf) & 0xefc60000) & 0xffffffff
	number =( uVar2 ^ claripy.LShR(uVar2, 0x12)) & 0xffffffff
	return state, number

def m_seedRand(state,seed):
	state[0] = seed & 0xffffffff
	state[0x270] = 1 & 0xffffffff
	while (state[0x270] < 0x270):
		state[state[0x270]] = (state[state[0x270] - 1] * 0x17b5) & 0xffffffff
		state[0x270] = (state[0x270] + 1) & 0xffffffff
	return state



from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
#r = remote("bin.training.jinblack.it", 2020)
r = process("./pnrg")

#final = r.recv(10)
#print("final: " + str(final))
#final1 = claripy.BVV(final, 10*8)

# for testing I am using final1 = 0x379d9d91 and seed = 0xf976cf33
final1 = 0x6c31f24d   
# seed = 0x4c8ea3e8

input = final1 
#input = input("Insert the number to recover its seed: ")    
#input = int(str(input), 16)
#input = input & 0xffffffff

print("input: " + str(input))
state = [0]*0x280

# start = claripy.BVV(0x03e8, 16) this shouldn't be needed since in m_rand we bitwise-and(ed) the seed and 0xfffffffff(so we can ignore the 3e8)
seed = claripy.BVS("seed", 32)
state = m_seedRand(state, seed)

for i in range(1000):
	state, number = genRandLong(state)
state, number = genRandLong(state)
number = number & 0xffffffff

solver = claripy.Solver()
solver.add(number == input) # last number generated has to be equal to the one we give
print("evaluating solution....")
try:
	solution = solver.eval(seed, 1)
	print(hex(solution[0]))
except:
	print("couldn't solve :(")