#!/usr/bin/env python3
#alias pwninit='pwninit --template-path ~/Downloads/pydgb/pwninit-template.py --template-bin-name self.elf --template-libc-name self.libc --template-ld-name self.ld'
from pydbg import *

script = """
source ~/.gdbinit-gef.py
handle SIGALRM nopass
"""

class Chall(Debugger):
    def __init__(self, remote=False, aslr=False, debug=True):
        self.remote = remote
        {bindings}
        if not remote:
            Debugger.__init__(self, self.elf.path, aslr=aslr, env={{"LD_PRELOAD": self.libc.path}}, script=script)
        else:
            self.p = remote("", _)
   
   def close(self):
	if not self.remote:
		Debugger.close(self)
	else:
		self.p.close()
			
   def pwn():
   	pass

def main():
    dbg = Chall()
    dbg.pwn()    
    
if __name__ == "__main__":
    main()        
