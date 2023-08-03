from gdb_plus import *

gdbinit = """
handle SIGALRM nopass
continue
"""

# This challenge implement a rubik's cube, but the moves aren't mapped so we have to understand which function corresponds to which action 
dbg = Debugger("./challenges/cube", script=gdbinit)

print(dbg.p.recv())
dbg.interrupt()
# The functions take as parameter a pointer to the cube which is an array of 54 longs
pointer = dbg.alloc(54 * 8)
# From ghidra we recover the array of possible actions
for move in [0x00003175, 0x00003e74, 0x000038d9, 0x00001885, 0x00001cdb, 0x000029e5, 0x00002da9, 0x00002131, 0x0000258b, 0x000027b8, 0x0000235e, 0x00002f8f, 0x00002bc7, 0x00001f06, 0x00001ab0, 0x00003b9d, 0x0000437c, 0x00003527]:
	# We mark each element of our cube in order
	dbg.write_longs(pointer, list(range(54)))
	# The binary is PIE so we calculate the real address of the function
	# Call the function with pointer as argument
	dbg.call(move, [pointer])
	print(f"results for function {hex(move)}")
	for i in range(54):
		# Read how the cube has been modified
		print(f"{i} -> {u64(dbg.read(pointer+i*8, 8))}")
dbg.close()	