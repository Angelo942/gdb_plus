"""describe_syscall() formats what set_strace() prints."""
import pytest
from pwn import context, pack

from gdb_plus.utils.syscalls import MAX_ARGV, MAX_BYTES, SIGNATURES, describe_syscall, syscall_names
from support.offline import offline_debugger


class Memory:
    def __init__(self, contents=None):
        self.contents = dict(contents or {})  # address -> bytes

    def read(self, address, size):
        for start, data in self.contents.items():
            if start <= address and address + size <= start + len(data):
                return data[address - start:address - start + size]
        return None

    def read_string(self, address, *, limit=0x100):
        data = self.read(address, 1)
        if data is None:
            raise MemoryError(hex(address))
        for start, content in self.contents.items():
            if start <= address < start + len(content):
                return content[address - start:].split(b"\x00")[0][:limit]


def describe(name, values, memory=None, arch="amd64"):
    memory = memory or Memory()
    with context.local(arch=arch):
        number = {v: k for k, v in syscall_names(arch).items()}[name]
        return describe_syscall(number, values + [0] * (6 - len(values)), memory.read, memory.read_string)


@pytest.mark.parametrize("arch, number, name", [
    ("amd64", 0, "read"), ("amd64", 1, "write"), ("amd64", 59, "execve"),
    ("i386", 4, "write"), ("i386", 11, "execve"), ("i386", 1, "exit"),  # 1 collides with socketcall's SYS_SOCKET
    ("aarch64", 64, "write"), ("aarch64", 221, "execve"),
])
def test_syscall_numbers(arch, number, name):
    """syscall_names(arch) maps this number to this syscall name for this architecture."""
    assert syscall_names(arch)[number] == name


def test_unknown_architecture_has_no_names():
    """syscall_names() of an unknown architecture is empty instead of raising."""
    assert syscall_names("not an arch") == {}


def test_every_signature_is_well_formed():
    """
    Every syscall signature uses a known argument kind, and each buffer refers to an argument that exists for its
    length.
    """
    kinds = {"d", "l", "u", "x", "o", "p", "s", "v", "m"}
    for name, signature in SIGNATURES.items():
        for field in signature.split():
            argument, kind = field.split(":")
            assert kind in kinds or (kind[0] == "b" and int(kind[1:]) < len(signature.split())), (name, field)


def test_buffer_uses_the_length_argument():
    """describe() of write shows only `count` bytes of the buffer."""
    memory = Memory({0x1000: b"hello world"})
    assert describe("write", [1, 0x1000, 5], memory) == ("write", "write(fd=1, buf='hello', count=5)")


def test_long_buffers_are_truncated():
    """A buffer longer than MAX_BYTES is cut and followed by "..."."""
    memory = Memory({0x1000: b"A" * 0x100})
    _, text = describe("write", [1, 0x1000, 0x100], memory)
    assert f"buf='{'A' * MAX_BYTES}'..." in text


def test_unreadable_pointers_are_shown_as_hex():
    """A pointer that can't be read is shown as a hex address instead of failing."""
    _, text = describe("write", [1, 0xdead0000, 5])
    assert "buf=0xdead0000" in text
    _, text = describe("open", [0xdead0000, 0, 0])
    assert "path=0xdead0000" in text


def test_null_pointers():
    """A NULL pointer argument is shown as NULL."""
    _, text = describe("open", [0, 0, 0])
    assert text.startswith("open(path=NULL")


def test_scalar_formats():
    """Scalar arguments use the right format: hex flags, octal modes, signed file descriptors and offsets."""
    memory = Memory({0x1000: b"/etc/passwd\x00"})
    assert describe("open", [0x1000, 0x241, 0o644], memory)[1] == "open(path='/etc/passwd', flags=0x241, mode=0644)"
    assert describe("close", [0xffffffff])[1] == "close(fd=-1)"
    assert describe("lseek", [3, 2**64 - 8, 2])[1] == "lseek(fd=3, offset=-8, whence=2)"
    assert "mode=0" in describe("open", [0x1000, 0, 0], memory)[1]


@pytest.mark.parametrize("prot, text", [(0, "PROT_NONE"), (1, "PROT_READ"), (7, "PROT_READ|PROT_WRITE|PROT_EXEC"), (8, "0x8")])
def test_memory_protections(prot, text):
    """mprotect's prot is shown as PROT_* names, or hex for an unknown value."""
    assert f"prot={text})" in describe("mprotect", [0x1000, 0x1000, prot])[1]


def test_argv_vectors():
    """execve's argv is shown as the list of strings it points to, and NULL envp as NULL."""
    argv = 0x2000
    memory = Memory({
        argv: pack(0x3000, 64) + pack(0x3010, 64) + pack(0, 64),
        0x3000: b"/bin/sh\x00".ljust(0x10, b"\x00"),
        0x3010: b"-c\x00",
    })
    _, text = describe("execve", [0x3000, argv, 0], memory)
    assert text == "execve(path='/bin/sh', argv=['/bin/sh', '-c'], envp=NULL)"


def test_argv_vectors_are_truncated():
    """An argv longer than MAX_ARGV is cut with "..."."""
    argv = 0x2000
    memory = Memory({argv: pack(0x3000, 64) * (MAX_ARGV + 2), 0x3000: b"x\x00"})
    _, text = describe("execve", [0x3000, argv, 0], memory)
    assert text.endswith(", ...], envp=NULL)")


def test_unknown_number_shows_every_register():
    """An unknown syscall number is shown as syscall_<n> with the six argument registers."""
    with context.local(arch="amd64"):
        name, text = describe_syscall(0xfff, [1, 2, 3, 4, 5, 6], Memory().read, Memory().read_string)
    assert name == "syscall_4095"
    assert text == "syscall_4095(0x1, 0x2, 0x3, 0x4, 0x5, 0x6)"


def test_known_name_without_signature_shows_every_register():
    """A known syscall without a signature shows its name and the six argument registers."""
    name, text = describe("sync", [])
    assert name == "sync" and "sync" not in SIGNATURES
    assert text == "sync(0x0, 0x0, 0x0, 0x0, 0x0, 0x0)"


def test_debugger_reads_the_syscall_number_from_orig_rax():
    """On amd64 the debugger takes the syscall number from orig_rax (rax already holds -ENOSYS at the entry)."""
    # On syscall entry rax already holds -ENOSYS, the number is in orig_rax
    with context.local(arch="amd64"):
        dbg = offline_debugger()
        dbg.memory.map(0x1000, b"hi\n")
        dbg.orig_rax, dbg.rax, dbg.rdi, dbg.rsi, dbg.rdx = 1, 2**64 - 38, 1, 0x1000, 3
        name, values, text = dbg._describe_syscall()
    assert name == "write"
    assert values[:3] == [1, 0x1000, 3]
    assert text == "write(fd=1, buf='hi\\n', count=3)"


def test_debugger_reads_the_syscall_number_on_aarch64():
    """On aarch64 the syscall number comes from x8 and the arguments from x0..."""
    with context.local(arch="aarch64"):
        dbg = offline_debugger()
        dbg.x8, dbg.x0 = 57, 3
        name, _, text = dbg._describe_syscall()
    assert (name, text) == ("close", "close(fd=3)")
