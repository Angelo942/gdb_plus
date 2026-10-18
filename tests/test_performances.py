from gdb_plus import *
import timeit

# 570 - 600ms
def test_startup():
    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False, from_entry = False) as dbg:
            ...

N = 3
duration_startup = timeit.timeit(test_startup, number=N, globals = globals())
print(f"time startup: {duration_startup / N * 1000:.0f}ms")

# Rip, there is no loader here
# def test_from_entry():
#     with context.local(binary="./traps_withSymbols"):
#         with Debugger(context.binary, aslr=False) as dbg:
#             ...

# duration = timeit.timeit(test_from_entry, number=N, globals = globals()) - duration_startup
# print(f"time from entry: {duration / N * 1000:.0f}ms")

# 1300ms
def test_debug_from():
    ANTI_DEBUG_TEST_FINISHED = 0x0401590
    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False, debug_from=ANTI_DEBUG_TEST_FINISHED) as dbg:
            ...

duration = timeit.timeit(test_debug_from, number=N, globals = globals()) - duration_startup
print(f"time debug_from: {duration / N * 1000:.0f}ms")

# 2000ms
def test_steps():
    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False) as dbg:
            for _ in range(10):
                dbg.si()

duration = timeit.timeit(test_steps, number=N, globals = globals()) - duration_startup
print(f"time 10 steps: {duration / N * 1000:.0f}ms")

# 70ms
def test_migration_libdebug():
    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False) as dbg:
            dbg.migrate(libdebug=True)

duration_migration_libdebug = timeit.timeit(test_migration_libdebug, number=N, globals = globals()) - duration_startup
print(f"time migration libdebug: {duration_migration_libdebug / N * 1000:.0f}ms")

# 160ms
def test_migration_new_libdebug():
    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False) as dbg:
            dbg.migrate(new_libdebug=True)

duration_migration_new_libdebug = timeit.timeit(test_migration_new_libdebug, number=N, globals = globals()) - duration_startup
print(f"time migration new_libdebug: {duration_migration_new_libdebug / N * 1000:.0f}ms")

# 2000ms
def test_steps_libdebug():
    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False) as dbg:
            dbg.migrate(libdebug=True)
            for _ in range(100):
                dbg.si()

duration = timeit.timeit(test_steps_libdebug, number=N, globals = globals()) - duration_migration_libdebug - duration_startup
print(f"time 100 steps (libdebug): {duration / N * 1000:.0f}ms")

# 2000ms
def test_steps_new_libdebug():
    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False) as dbg:
            dbg.migrate(new_libdebug=True)
            for _ in range(1000):
                dbg.si()

duration = timeit.timeit(test_steps_new_libdebug, number=N, globals = globals()) - duration_migration_new_libdebug - duration_startup
print(f"time 1000 steps (new_libdebug): {duration / N * 1000:.0f}ms")

# 15ms
def test_place_breakpoint():
    ANTI_DEBUG_TEST_FINISHED = 0x0401590
    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False) as dbg:
            dbg.b(0x4017f4)
            dbg.b(0x4017f6)
            dbg.b(0x4017f9)
            dbg.b(0x4017fa)

duration = timeit.timeit(test_place_breakpoint, number=N, globals = globals()) - duration_startup
print(f"time place breakpoint: {duration / N * 1000:.0f}ms")

# 410ms
def test_stop():
    def callback_stop(self):
        return True
        

    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False) as dbg:
            dbg.b(0x4017fa, callback=callback_stop)
            dbg.execute_action("c")
            self._priority_wait(comment="continue")

duration_stop = timeit.timeit(test_stop, number=N, globals = globals()) - duration_startup
print(f"time stop: {duration_stop / N * 1000:.0f}ms")

# 1600ms
def test_callback():
    def callback_pass(self):
        return False

    def callback_stop(self):
        return True
        

    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False) as dbg:
            dbg.b(0x4017f4, callback=callback_pass)
            dbg.b(0x4017f6, callback=callback_pass)
            dbg.b(0x4017f9, callback=callback_pass)
            dbg.b(0x4017fa, callback=callback_stop)
            # priority = dbg._raise_priority("continue")
            # dbg.gdb.execute("c")
            # dbg._priority_wait(comment="continue", priority = priority)
            print("---------------------------------")
            dbg.execute_action("continue", "continue")
            dbg._priority_wait(comment="continue")

duration = timeit.timeit(test_callback, number=N, globals = globals()) - duration_stop - duration_startup
print(f"time callback: {duration / N * 1000:.0f}ms")

# 100ms
def test_legacy_callback():
    ANTI_DEBUG_TEST_FINISHED = 0x0401590

    def callback_pass(self):
        return False

    def callback_stop(self):
        return True

    with context.local(binary="./traps_withSymbols"):
        with Debugger(context.binary, aslr=False) as dbg:
            dbg.b(0x4017f4, legacy_callback=callback_pass)
            dbg.b(0x4017f6, legacy_callback=callback_pass)
            dbg.b(0x4017f9, legacy_callback=callback_pass)
            dbg.b(0x4017fa, legacy_callback=callback_stop)
            dbg.execute_action("c")
            dbg._priority_wait(comment="continue")


duration = timeit.timeit(test_legacy_callback, number=N, globals = globals()) - duration_stop - duration_startup
print(f"time legacy_callback: {duration / N * 1000:.0f}ms")

