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
source /home/root/pwndbg/gdbinit.py
"""

QUICK = 10
MEDIUM = 30
LONG = 60

#@unittest.skip
class Debbuger_new_libdebug(unittest.TestCase):
    from base64 import b64encode
    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        warnings.simplefilter("ignore", ImportWarning)

    def tearDown(self):
        pass

    @timeout_decorator.timeout(LONG)
    def test_ptrace_emulation_new_libdebug(self):
        print("\ntest_ptrace_emulation_new_libdebug: ", end="")
        with context.local(binary="./traps_withSymbols"):
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
            with Debugger(context.binary, aslr=False, debug_from=END_ANTI_TRACING) as dbg:
                dbg.set_split_on_fork()
                dbg.emulate_ptrace(silent=False)

                # split children and parent
                dbg.continue_until("fork")
                dbg.finish()
                child_pid = dbg.wait_split()
                child = dbg.children[child_pid]
                child.emulate_ptrace(silent=False)

                A, b = [], []
                dbg.p.sendline(b"A"*0x40)
                
                child.migrate(libdebug=True) # Can not use new_libdebug here
                dbg.migrate(new_libdebug=True)
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
                from sage.all import IntegerModRing, MatrixSpace, vector
                R = IntegerModRing(2**32)
                M = MatrixSpace(R, 0x10, 0x10)
                A = M(A)
                b = vector(b)
                x = A.solve_right(b)
                flag = b""
                for n in x:
                    flag += p32(n)
                self.assertEqual(xor(flag, 0xd), b"CSCG{4ND_4LL_0FF_TH1S_W0RK_JU5T_T0_G3T_TH1S_STUUUP1D_FL44G??!!1}")


if __name__ == "__main__":
    with context.quiet:
        unittest.main()
