# These test fail for unknown reason


import unittest
from gdb_plus import *

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

	#@unittest.skip
	def test_my_split(self):
		print("\ntest_my_split: ", end="")
		with context.local(arch = 'amd64'):
			dbg = Debugger("./traps_withSymbols", script="set detach-on-fork off", aslr=False)
			def fork_handler(event):
				inferior = event.inferior
				print(inferior)
				pid = inferior.pid     
				if dbg.running: 	  
					dbg.interrupt()
				def split(inferior):
					ip = dbg.instruction_pointer
					print(hex(ip))
					inferior.write_memory(ip, b"\x90")
				context.Thread(target=split, args = (inferior,)).start()
			dbg.gdb.events.new_inferior.connect(fork_handler)
				
			dbg.c(wait=False)
			pid = dbg.wait_split() # and then for the child to split out
			dbg.p.interactive()

if __name__ == '__main__':
	unittest.main()
