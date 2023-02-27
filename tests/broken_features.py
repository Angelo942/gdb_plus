# These test fail for unknown reason


import unittest
from gdb_plus import *


# Here the breakpoint on HANDLER_RET is temporary, but for some reason gdb doesn't registers the hit even if the callback function gets called
class Debugger_breakpoints(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		from queue import Queue

	def put_breakpoint(self, dbg, *, outputs, comment, address, return_value=None):
		comments = [comment]
		return_values = [return_value]
		def callback(dbg):
			print(comments[0])
			outputs.append(comments[0])
			print(f"return value is {return_values[0]}")
			return return_values[0]
		dbg.b(address, callback=callback, temporary=True)

	# Metti anche un return False o return True
	def test_callback(self):
		START = 0x8048060
		dbg = Debugger("./start")
		outputs = []
		self.put_breakpoint(dbg, outputs=outputs, comment="forth", address=START, return_value=False) # should continue
		dbg.execute(f"jump *{hex(START)}")
		self.assertEqual(dbg.recv(), b"Let's start the CTF:")
		dbg.interrupt()
		self.put_breakpoint(dbg, outputs=outputs, comment="fith", address=START, return_value=True) # should break
		dbg.execute(f"jump *{hex(START)}")
		dbg.wait()
		dbg.close()
		self.assertEqual(outputs, ["forth", "fith"]) # Invece il breakpoint 4 non viene cancellato perchè ritorno False

	# I would like to be able to put breakpoints even when the process is running
	def test_breakpoint_while_running(self):
		dbg = Debugger("./start")
		dbg.c()
		START = 0x8048060
		dbg.b(START)
		dbg.b(START - dbg.elf.address)
		dbg.b(START, callback=lambda dbg: True)
		dbg.p.interactive()


class Debbuger_fork(unittest.TestCase):
	from base64 import b64encode
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)

	def http_request(self, *, auth: bytes = b64encode(b"admin:admin"), keepAlive: bool = False):
		LINE_TERMINATOR =  b"\r\n"
		request = []
		request.append(b"GET / HTTP/1.1")
		request.append(b"authorization: Basic " + auth) 
		if keepAlive:
			request.append(b"Connection: keep-alive")
		else:
			request.append(b"Connection: close")
		return LINE_TERMINATOR.join(request + [b""])

	def test_continuous_follow(self):
		gdbscript = """
		set detach-on-fork off
		set follow-fork-mode child
		"""
		dbg = Debugger("./httpd", aslr=False, script=gdbscript)
		CALL_TO_B64DECODE = 0x26d5
		dbg.b(CALL_TO_B64DECODE)
		dbg.c()
		dbg.p.sendline(self.http_request(keepAlive=True))
		dbg.wait()
		self.assertEqual(dbg.rip, 0x5555555566d5)
		dbg.c() # Don't forget to switch only after the child has continued
		# do what you want and go back to the parent once you are done (you can also do it after the children death)
		print("the first child is dead")
		# TODO find an alternative than waiting for the child to die
		#dbg.wait() # Non riceve mai il segnale che è finito...
		dbg.wait(timeout=1) # Va bene come alternativa ?
		dbg.execute("inferior 1") # We can't go back while the child is running
		dbg.c()
		dbg.p.sendline(self.http_request(keepAlive=True))
		dbg.wait()
		self.assertEqual(dbg.rip, 0x5555555566d5)
		dbg.close()

	# I would like to use follow-fork-mode parent, but the callback isn't called even with detach-on-fork off
	#def test_callbacks(self):
	#	gdbscript = """
	#	set detach-on-fork off
	#	set follow-fork-mode child
	#	"""
	#	from queue import Queue
	#	my_instruction_pointer = Queue()
	#	def callback(dbg):
	#		#self.assertEqual(dbg.rip, 0x5555555566d5)
	#		print("callback called")
	#		my_instruction_pointer.put(dbg.instruction_pointer)
	#		return False # Continue execution
	#	dbg = Debugger("./httpd", aslr=False, script=gdbscript)
	#	CALL_TO_B64DECODE = 0x26d5
	#	dbg.b(CALL_TO_B64DECODE, callback=callback)
	#	dbg.c()
	#	dbg.p.sendline(self.http_request(keepAlive=True))
	#	print("call get")
	#	self.assertEqual(my_instruction_pointer.get(), 0x5555555566d5)
	#	print("part 1 done")
	#	dbg.p.sendline(self.http_request(keepAlive=True))
	#	self.assertEqual(my_instruction_pointer.get(), 0x5555555566d5)
	#	dbg.close()		

class Debug_alloc(unittest.TestCase):

	def test_dealloc_bss(self):
		dbg = Debugger("./cube", from_start=False)
		pointer_1 = dbg.alloc(100, heap=False)
		pointer_2 = dbg.alloc(  8, heap=False)
		dbg.write(pointer_2, p64(0xdeadbeefdeadbeef))
		dbg.dealloc(pointer_1, len=100, heap=False)
		pointer_3 = dbg.alloc(100, heap=False)
		dbg.write(pointer_3, b"\x00"*100)
		out = dbg.read(pointer_2, 8)
		dbg.close()
		self.assertEqual(out, p64(0xdeadbeefdeadbeef)) # Is overwriten because the delloc only removes 100 bytes from the end of the bss

#class Debug_base_elf(unittest.TestCase):
#
#	# patchelf may add a page before the binary wich can give us a wrong base
#	def test_base_address(self):
#		pass

if __name__ == '__main__':
	unittest.main()
