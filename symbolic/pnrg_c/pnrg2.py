from os import stat
import numpy as np
import re
import z3
import claripy
import sys
s=z3.Solver()
seed = z3.BitVec("seed", 33)

#note that there may be collisions and require more attempts for it to work properly

def mag(i):
    return z3.If(i == 0, z3.BitVecVal(0x0, 33), z3.BitVecVal(0x9908b0df, 33))
    
def seedRand(state, seed):
    result=0
    state[0]=seed
    state[0x270]=1
    for state[0x270] in range (1,0x270,1):
        result=state[0x270]
        if(result > 623):
            break
        state[state[0x270]]=state[state[0x270]-1]*6069
    return state
    
def genRandLong(state):
    if(state[0x270] >= 0x270):
        if(state[0x270] >= 0x271):
            seedRand(state, 4357)
        for x in range(227):
            v4=state[x]&0x80000000 | state[x+1] & 0x7fffffff
            p1=mag(v4&1) &0xffffffff
            p2=(v4>>1)&0xffffffff
            p3=state[x+397]&0xffffffff
            state[x]=p1 ^ p2 ^ p3
        while(x<=622):
            v5=state[x]&0x80000000 | state[x+1] & 0x7fffffff
            p1=mag(v5&1)&0xffffffff
            p2=(v5>>1)&0xffffffff
            p3=state[x-227]&0xffffffff
            state[x]=p1 ^ p2 ^ p3
            x=x+1
        v6=state[623]&0x80000000 | state[0] & 0x7fffffff
        p1=mag(v6&1)&0xffffffff
        p2=(v6>>1)&0xffffffff
        p3=state[396]&0xffffffff
        state[623]=(p1 ^ p2) ^ p3
        state[0x270]=0
    v1=state[0x270]&0xffffffff
    state[0x270]=v1+1&0xffffffff
    v7=((state[v1]>>11)^state[v1])&0xffffffff
    v8=((((v7<<7)&0x9d2c5680^v7)<<15)&0xefc60000^(v7<<7)&0x9d2c5680 ^ v7)&0xffffffff
    return state,(v8>>18)^v8
state=([0]*0x300)
state=seedRand(state, seed)
b=np.longlong
for m in range(1001): #1001
    state, b=genRandLong(state)
    
state, b=genRandLong(state)

print("\n")
#print(sys.getsizeof(b)) #56 bit obviously
# the idea is to run two terminals. The first one in remote and we take the value and use it in the other terminal in local.
# obv all can be done with input python cmd
s.add(b==0xcac9e492)
s.check()
print(s.model())
from IPython import embed
embed()