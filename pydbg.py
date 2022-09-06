from pwn import *
from os import kill

stopped = False

def stop(*args):
	global stopped
	stopped = True

def wait(timeout=1):
	dt = 0.05
	global stopped
	while not stopped and timeout > 0:
		sleep(dt)
		timeout -= dt
	stopped = False
	
class Debugger:
	def __init__(self, target, env={}, aslr=False, script=None):
		self.p = process(target, env=env, aslr=aslr)
		self.attach(script)
		
	def attach(self, script):
		_, self.gdb = gdb.attach(self.p, gdbscript=script, api=True)
		self.gdb.events.stop.connect(stop)
		self.inferior = self.gdb.inferiors()[0]
		
	def get_base_libc(self):
		data = self.execute("info files")
		for line in data.split("\n"):
			if "libc" in line and line.startswith("	0x"):
				address = int(line.split()[0], 16)
				return address - address%0x1000

	def get_base_elf(self):
		data = self.execute("info files")
		for line in data.split("\n"):
			if line.startswith("	Entry point:"):
				address = int(line.split()[-1], 16)
				return address - address%0x1000
		
	#per interrompere l'esecuzione e riprendere il controllo nella shell gdb
	def manual(self):
		kill(self.p.pid, signal.SIGINT)
		
	def alloc(self, n): #Funziona solo se hai una libc con malloc ovviamente
		pointer = self.gdb.execute(f"call (long) malloc({n})", to_string=True).split()[-1]
		return int(pointer)
	
	def read(self, address: int, size: int):
		return self.inferior.read_memory(address, size).tobytes()
		
	def write(self, pointer, byte_array):
		self.inferior.write_memory(pointer, byte_array)

	def execute(self, code: str):
		return self.gdb.execute(code, to_string=True)
	
	def b(self, address):
		#devo ancora capire cosa succede quando arriva sopra
		if type(address) is int:
			address = f"*{hex(address)}"
		self.gdb.Breakpoint(address)
		
	breakpoint = b
	
	def c(self, timeout=1):
		global stopped
		stopped = False
		#self.gdb.events.stop.connect(stop)
		self.execute("continue")
		wait(timeout) #timeout = 0 equivale a no wait
	
	def signal(self, n):
		#dato che signal fa anche continuare il programma devo usare wait
		self.execute(f"signal {n}")
		wait()

	def close(self):
		try:
			self.execute("quit")
		except Exception:
			pass #quando muore gdb raisa EOF

	@property
	def canary(self):
		if not self.p.elf.canary:
			return none
		if self.p.elf.bits == 32:
			pointer = self.ebp
			sleep(0.2)
			return self.read(pointer - 4, 4)
		else:
			return self.read(self.rbp - 8, 8)

	@property
	def rax(self):
		return int(self.gdb.parse_and_eval("$rax"))

	@rax.setter
	def rax(self, value):
		self.execute(f"set $rax = {value}")
		 
			
	@property
	def eax(self):
		return int(self.gdb.parse_and_eval("$eax"))

	@eax.setter
	def eax(self, value):
		self.execute(f"set $eax = {value}")
		 
			
	@property
	def rbx(self):
		return int(self.gdb.parse_and_eval("$rbx"))

	@rbx.setter
	def rbx(self, value):
		self.execute(f"set $rbx = {value}")
		 
			
	@property
	def ebx(self):
		return int(self.gdb.parse_and_eval("$ebx"))

	@ebx.setter
	def ebx(self, value):
		self.execute(f"set $ebx = {value}")
		 
			
	@property
	def rcx(self):
		return int(self.gdb.parse_and_eval("$rcx"))

	@rcx.setter
	def rcx(self, value):
		self.execute(f"set $rcx = {value}")
		 
			
	@property
	def ecx(self):
		return int(self.gdb.parse_and_eval("$ecx"))

	@ecx.setter
	def ecx(self, value):
		self.execute(f"set $ecx = {value}")
		 
			
	@property
	def rdx(self):
		return int(self.gdb.parse_and_eval("$rdx"))

	@rdx.setter
	def rdx(self, value):
		self.execute(f"set $rdx = {value}")
		 
			
	@property
	def edx(self):
		return int(self.gdb.parse_and_eval("$edx"))

	@edx.setter
	def edx(self, value):
		self.execute(f"set $edx = {value}")
		 
			
	@property
	def rdi(self):
		return int(self.gdb.parse_and_eval("$rdi"))

	@rdi.setter
	def rdi(self, value):
		self.execute(f"set $rdi = {value}")
		 
			
	@property
	def edi(self):
		return int(self.gdb.parse_and_eval("$edi"))

	@edi.setter
	def edi(self, value):
		self.execute(f"set $edi = {value}")
		 
			
	@property
	def rsi(self):
		return int(self.gdb.parse_and_eval("$rsi"))

	@rsi.setter
	def rsi(self, value):
		self.execute(f"set $rsi = {value}")
		 
			
	@property
	def esi(self):
		return int(self.gdb.parse_and_eval("$esi"))

	@esi.setter
	def esi(self, value):
		self.execute(f"set $esi = {value}")
		 
			
	@property
	def rsp(self):
		return int(self.gdb.parse_and_eval("$rsp"))

	@rsp.setter
	def rsp(self, value):
		self.execute(f"set $rsp = {value}")
		 
			
	@property
	def esp(self):
		return int(self.gdb.parse_and_eval("$esp"))

	@esp.setter
	def esp(self, value):
		self.execute(f"set $esp = {value}")
		 
			
	@property
	def rbp(self):
		return int(self.gdb.parse_and_eval("$rbp"))

	@rbp.setter
	def rbp(self, value):
		self.execute(f"set $rbp = {value}")
		 
			
	@property
	def ebp(self):
		return int(self.gdb.parse_and_eval("$ebp"))

	@ebp.setter
	def ebp(self, value):
		self.execute(f"set $ebp = {value}")
		 
			
	@property
	def rip(self):
		return int(self.gdb.parse_and_eval("$rip"))

	@rip.setter
	def rip(self, value):
		self.execute(f"set $rip = {value}")
		 
			
	@property
	def eip(self):
		return int(self.gdb.parse_and_eval("$eip"))

	@eip.setter
	def eip(self, value):
		self.execute(f"set $eip = {value}")
		 
			
	@property
	def r8(self):
		return int(self.gdb.parse_and_eval("$r8"))

	@r8.setter
	def r8(self, value):
		self.execute(f"set $r8 = {value}")
		 
			
	@property
	def r9(self):
		return int(self.gdb.parse_and_eval("$r9"))

	@r9.setter
	def r9(self, value):
		self.execute(f"set $r9 = {value}")
		 
			
	@property
	def r10(self):
		return int(self.gdb.parse_and_eval("$r10"))

	@r10.setter
	def r10(self, value):
		self.execute(f"set $r10 = {value}")
		 
			
	@property
	def r11(self):
		return int(self.gdb.parse_and_eval("$r11"))

	@r11.setter
	def r11(self, value):
		self.execute(f"set $r11 = {value}")
		 
			
	@property
	def r12(self):
		return int(self.gdb.parse_and_eval("$r12"))

	@r12.setter
	def r12(self, value):
		self.execute(f"set $r12 = {value}")
		 
			
	@property
	def r13(self):
		return int(self.gdb.parse_and_eval("$r13"))

	@r13.setter
	def r13(self, value):
		self.execute(f"set $r13 = {value}")
		 
			
	@property
	def r14(self):
		return int(self.gdb.parse_and_eval("$r14"))

	@r14.setter
	def r14(self, value):
		self.execute(f"set $r14 = {value}")
		 
			
	@property
	def r15(self):
		return int(self.gdb.parse_and_eval("$r15"))

	@r15.setter
	def r15(self, value):
		self.execute(f"set $r15 = {value}")
		 
