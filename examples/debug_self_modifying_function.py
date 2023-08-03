from gdb_plus import *
from queue import Queue

# In this challenge the process writes an encrypted function somewhere in the memory. Every int3 instructions should raise a signal that is handled decrypting the next few bytes of the function
# The file has been patched to expect SIGUSR1 instead of SIGINT to prevent problems with gdb
dbg = Debugger("./challenges/ExceptionalChecking_patched")

# Address of the ret instruction in the handler function. We are sure that the next instructions have been decrypted when we reach this instruction
HANDLER_RET = 0x04011ff
# Address from where we want to analyse our process
CHECK_CALL = 0x0401341

# The folowing part is commented out because the new version of signal now does it under the hood
## Since the code is self modifying we can not put breakpoints before the handler is called
#my_instruction_pointer = Queue()
#def callback_signal_handler(dbg):
#	dbg.breakpoint(my_instruction_pointer.get(), temporary=True)
#	return False
## We therefore save our address in a queue and set our breakpoint only when the handler finishes executing 
## Warning we are setting a breakpoint with a callback so we have to be sure that the process isn't running.
#dbg.breakpoint(HANDLER_RET, callback=callback_signal_handler)

# Put a breakpoint before the check functions is called
dbg.breakpoint(CHECK_CALL, temporary=True)

# Continue the execution
done = dbg.until(CHECK_CALL, wait=False)
dbg.p.sendline(b"serial_a_caso")
# Wait for the process to reach our breakpoint on CHECK_CALL
done.wait()

# We step inside the funciton
dbg.step()

# We set a flag to know if the previous instruction was a int3
dbg.call_signal = False
code = b""

def callback(dbg):
	global code
	if dbg.call_signal:
		## Save the address we are at
		#my_instruction_pointer.put(dbg.rip)
		# Send the signal to the process
		dbg.signal("SIGUSR1", handler=HANDLER_RET)
		## Wait for the handler to decrypt the code and return to our function
		#dbg.wait()
		dbg.call_signal = False
	ni = dbg.next_inst
	if ni.mnemonic == "int3":
		dbg.call_signal = True
		# We nop the signal even if it isn't needed
		dbg.write(dbg.rip, b"\x90")
	print(ni.toString())
	# Save the code executed
	code += ni.bytes

# Advance step by step and call callback each time
dbg.step_until_ret(callback)

# Save the code executed in a file to be decompiled later and reverse the function
#with open("dump_ExceptionalChecking", "wb") as fp:		
#	fp.write(code.get())