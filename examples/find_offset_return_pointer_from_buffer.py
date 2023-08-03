from gdb_plus import Debugger
from pwn import *

# This challenge is a simple buffer overflow
dbg = Debugger("./challenges/start")

# Start execution
dbg.cont(wait=False)

dbg.p.sendline(cyclic(500))

# Wait for the process to segfault
dbg.wait()

# Our input has been loaded in the instruction pointer
pointer = dbg.instruction_pointer % 2**32 #If the binary is 64bits we only take the last 4 bytes of our instruction pointer
offset = cyclic_find(p32(pointer))

print(offset)

# We close this process and you can launch a new one to attack
dbg.close()