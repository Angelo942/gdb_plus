"""httpd (amd64, PIE, forks for every connection): follow-fork, split, migrate."""
from base64 import b64encode

import pytest

CALL_TO_B64DECODE = 0x26d5


def http_request(auth=b64encode(b"admin:admin"), keep_alive=False):
    lines = [b"GET / HTTP/1.1", b"authorization: Basic " + auth,
             b"Connection: keep-alive" if keep_alive else b"Connection: close"]
    return b"\r\n".join(lines + [b""])


@pytest.fixture
def httpd(challenge):
    return challenge("httpd")


@pytest.mark.timeout(90)
def test_follow_the_child(debugger, httpd):
    """
    On a server that forks per connection, gdb's follow-fork-mode child: a breakpoint before b64decode is hit in the
    child of each of two requests.
    """
    dbg = debugger(httpd, aslr=False, script="set detach-on-fork off\nset follow-fork-mode child\n")
    done = dbg.until(CALL_TO_B64DECODE, wait=False)
    dbg.p.sendline(http_request(keep_alive=True))
    done.wait()
    assert dbg.rip == 0x5555555566d5
    dbg.c()
    dbg.execute("inferior 1")
    done = dbg.until(CALL_TO_B64DECODE, wait=False)
    dbg.p.sendline(http_request(keep_alive=True))
    done.wait()
    assert dbg.rip == 0x5555555566d5


@pytest.mark.timeout(90)
def test_split_an_inferior(debugger, httpd):
    """
    _split_child() turns the forked child gdb holds into its own Debugger that stops at b64decode for one request, while
    the parent keeps serving the next one.
    """
    import time
    dbg = debugger(httpd, aslr=False, script="set detach-on-fork off\nset follow-fork-mode parent\n")
    dbg.c(wait=False)
    time.sleep(1)  # the child is created and stopped at fork while the parent keeps running
    dbg.interrupt()
    time.sleep(1)
    assert not dbg.priority
    dbg.b(CALL_TO_B64DECODE)
    child = dbg._split_child(n=2)
    dbg.p.sendline(http_request(keep_alive=True))
    child.b(CALL_TO_B64DECODE)
    child.c()
    assert child.rip == 0x5555555566d5
    child.c()
    child.detach()
    dbg.execute("set follow-fork-mode child")
    dbg.p.sendline(http_request(keep_alive=True))
    dbg.c()
    time.sleep(1)
    assert dbg.rip == 0x5555555566d5


@pytest.mark.libdebug
def test_migrate_back_and_forth(debugger, httpd):
    """migrate() gdb → libdebug → gdb at the entry of httpd: step() works and the position is kept with each engine."""
    dbg = debugger(httpd, aslr=False)
    dbg.migrate(libdebug=True)
    assert dbg.instruction_pointer == 0x555555555440
    dbg.step()
    assert dbg.instruction_pointer == 0x555555555444
    dbg.migrate(gdb=True)
    assert dbg.instruction_pointer == 0x555555555444
    dbg.step()
    assert dbg.instruction_pointer == 0x555555555446


@pytest.mark.libdebug
def test_continue_until_with_libdebug(debugger, httpd):
    """continue_until("main") with the legacy libdebug stops at httpd's main."""
    dbg = debugger(httpd, aslr=False)
    dbg.migrate(libdebug=True)
    dbg.continue_until("main")
    assert dbg.instruction_pointer == 0x55555555570c
