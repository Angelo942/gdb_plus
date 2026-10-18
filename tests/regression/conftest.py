"""
The CTF challenges of the legacy suite (tests/test_old.py, test_Structure.py, test_new_libdebug.py),
replayed with the same addresses and the same expectations. If one of these breaks, a script that
used to work for a user is broken too.
"""
import pytest
from pwn import context


@pytest.fixture
def challenge(ctf_binary):
    """challenge("cube") -> copy of the binary in the test directory, also set as context.binary"""
    def get(name, **kwargs):
        path = ctf_binary(name, **kwargs)
        context.binary = path
        return path
    return get


def parse_matrix_line(data: bytes):
    from pwn import u32
    return [u32(data[i * 4:(i + 1) * 4]) for i in range(0x10)]


def solve_traps_matrix(A, b):
    """The last step of the 'traps' writeup: solve A x = b over Z/2^32 with Sage."""
    from pwn import p32, xor
    from sage.all import IntegerModRing, MatrixSpace, vector
    ring = IntegerModRing(2**32)
    x = MatrixSpace(ring, 0x10, 0x10)(A).solve_right(vector(b))
    return xor(b"".join(p32(int(n)) for n in x), 0xd)
