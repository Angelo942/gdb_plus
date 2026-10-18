import signal

import pytest

from gdb_plus.utils.signals import SIGNALS, SIGNALS_from_num


def test_lookup_tables_are_inverse():
    """SIGNALS (name → number) and SIGNALS_from_num (number → name) are inverse tables."""
    for number in range(1, len(SIGNALS_from_num)):
        assert SIGNALS[SIGNALS_from_num[number]] == number


def test_all_standard_signals_are_listed():
    """The 31 standard signals are listed, and entry 0 is not a signal."""
    assert len(SIGNALS_from_num) == 32
    assert SIGNALS_from_num[0] not in SIGNALS


@pytest.mark.parametrize("name, number", sorted(SIGNALS.items()))
def test_numbers_match_the_linux_kernel(name, number):
    """Each signal number in SIGNALS is the number Python's signal module (the Linux kernel) uses on x86-64."""
    if not hasattr(signal, name):
        pytest.skip(f"{name} is not defined by python on this platform")
    assert getattr(signal, name) == number
