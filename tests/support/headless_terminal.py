#!/usr/bin/env python3
"""
Stand-in for a terminal emulator so that gdb can run without opening a window.

pwntools launches gdb through `context.terminal + [command]`. We give gdb a
pseudo terminal (it refuses to stay alive with stdin on /dev/null), drain its
output so it never blocks on a full pty buffer, and exit when gdb exits.
When we are killed (pwntools does it at exit, the test suite after each test)
the whole process group of gdb goes with us.

Usage: context.terminal = [sys.executable, "headless_terminal.py"]
"""
import os
import pty
import signal
import sys
import time


def main():
    command = sys.argv[1:]
    if len(command) == 1 and not (os.path.isfile(command[0]) and os.access(command[0], os.X_OK)):
        # A shell command string. pwntools usually passes the path of a script instead, which we exec directly
        command = ["/bin/sh", "-c", command[0]]

    log_path = os.environ.get("GDB_PLUS_TERMINAL_LOG")
    log = open(log_path, "ab", buffering=0) if log_path else None

    # The child is a session leader with the pty as controlling terminal: its pid is also its process group
    pid, master = pty.fork()
    if pid == 0:
        os.execvp(command[0], command)

    def stop(signum, _frame):
        for sig in [signal.SIGHUP, signal.SIGTERM]:
            try:
                os.killpg(pid, sig)
            except OSError:
                break
            time.sleep(0.3)
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)

    while True:
        try:
            data = os.read(master, 0x1000)
        except OSError:
            break
        if not data:
            break
        if log is not None:
            log.write(data)
    os.waitpid(pid, 0)


if __name__ == "__main__":
    main()
