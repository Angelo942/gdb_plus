# GDB+
*Python library to automate gdb debugging* 

GDB+ is a wrapper around gdb powered by pwntools. The goal is automate your interactions with gdb and add some extra features.

## Main features

* Bypass ptrace anti-debugging.
* Include python functions as callback to your breakpoint.
* Test / Bruteforce a specific functions of a binary with the parameters you want.
* Log the code of a self modifying function.
* Backup parts of your memory and restore it during future executions.
* For pwning don't worry about making a separate script to debug your exploit. The arguments `NOPTRACE` and `REMOTE` make the exploit skip any action related to gdb or attack directly the remote server.

## Installation

### System requirements

First make sure to have `gdb` and `gdbserver` installed.

```bash
sudo apt install gdb gdbserver
```

If you want to debug `ARM` and `RISCV` binaries you will also need `qemu` and `gdb-multiarch`.

```bash
sudo apt install gdb-multiarch qemu-user
```

See the chapter about [QEMU](#qemu) for more informations on how to set up the system libraries for the architecture you want to emulate and some limitations when debugging under the emulator.

### gdb_plus

stable version

```bash
pip3 install gdb_plus
```

or dev branch

```bash
pip3 install git+https://github.com/Angelo942/gdb_plus.git@dev
```

**Warning for pwndbg users:**  
Previous bugs in Pwndbg used to break the api for python. While most of GDB+ should work with the current version of pwndbg [19/12/2022] some problems may arise while emulating ptrace.
you are strongly advised to use [GEF](https://github.com/hugsy/gef) instead except if using QEMU for which pwndbg is currently a better option [18/01/25].

## Script setup
GDB+ is using pwntools to work with the correct architecture. It is recommended to set the `context` at the beginning of your script. You can directly use the binary if it's an ELF or the architecture (and if needed the bit size).

```py
from gdb_plus import *
exe = ELF("./challenge")
context.binary = exe

dbg = Debugger(exe)
...
```

```py
from gdb_plus import *
context.arch = "amd64"

dbg = Debugger("./challenge")
...
```

pwntools also gives you arguments that you can pass to the script to change the behaviour. In particular we use `NOPTRACE` and `REMOTE`. `python3 ./script.py NOPTRACE` sets `Debugger.debugging` to `False` and skips all actions with gdb. `python3 ./script.py REMOTE` connects to the server specified as `Debugger.setup_remote(<host>, <port>)` to launch the attack instead of spawning a local process.

If you want here are a template for spwn [template_spwn.py](./examples/template_spwn.py) and pwninit [template_pwninit.py](./examples/template_pwninit.py)

## Debugging

You can debug a program using the path to the binary.   
If you really have to you can also use a process or even just his pid.
For programs running in a container you can connect directly to a given gdbserver.
For pwn challenges set the remote address with `Debugger.setup_remote(<host>, <port>)` and use the argument `REMOTE` once you want to exploit the server

```py
from gdb_plus import *

gdbinit = """
handle SIGALRM nopass
"""

dbg = Debugger("./rev_challenge", script=gdbinit, aslr=False)

dbg = Debugger("./pwn_challenge", script=gdbinit)
dbg.setup_remote("10.10.0.1", 1337)


p = process("./challenge", aslr=False)
dbg = Debugger(p, script=gdbinit)

#pidof process : 3134
dbg = Debugger(3134, script=gdbinit, binary="./challenge")

# gdbserver running on 192.168.1.234:2345
dbg = Debugger(("192.168.1.234", 2345), script=gdbinit, binary="./challenge")
```

By default your process will be analysed from the first instruction of the loader. If the process you are debugging has some checks you want to avoid use `Debugger(..., debug_from=<address>)` to attach with gdb at a specific address.  
This will block you script until you reach you address. If you need to execute code in between you can use the non blocking alternative: 

```py
Im_done = Event()
dbg = Debugger("./challenge").debug_from("main+0x34", event=Im_done)
dbg.p.sendline("this is my input")
Im_done.set()
dbg.debug_from_done.wait()
```

This should pass any check for a debugger, even searches for INT3, except a full check that the code hasn't been edited.

Calling your script with pwntools arguments `NOPTRACE` or `REMOTE` will allow you to disable all actions related to gdb and test your exploit locally or attack the remote target without having to comment anything. If you want a finer control you can use `ìf dbg.debugging` to discriminate the code that should be executed when gdb is opened or not.

**Note**  
Debugger can also take as parameter a dictionary for the environment variables. You CAN use it to preload libraries, but if you want to do it for the libc I would advise to **patch the rpath** of the binary instead (if you don't know how take a look at [spwn](https://github.com/MarcoMeinardi/spwn) or [pwninit](https://github.com/io12/pwninit). This will prevent problems when running `system("/bin/sh")` that will fail due to LD_PRELOAD and may hide other problems in your exploit.

**Warning**  
Old versions of gdbserver (< 11.0.50) have problems launching 32bit binaries. If you see a crash trying to find the canary use `from_start=False` as parameter for the debugger. This will launch the process and then attach to it once the memory has been correctly mapped. Letting `from_start=True` may also cause problems if the environment variables are important to your exploit since they will be mixed with some set up by gdbserver.

## Control Flow

The main actions for gdb are already wrapped in individual methods. For all commands not present you can reconstruct them by calling `Debugger.execute(<command>)` as if you where using gdb. if your command will require you to call `Debugger.wait()` make sure to use `Debugger.execute_action(<command>)` instead.

```py
dbg.jump() # set instruction pointer to specific address
dbg.step() # Single instruction (will enter function calls)
dbg.next() # Next instruction (will jump over function calls)
dbg.cont() # Continue execution
dbg.continue_until() # Continue until you reach a specific location
dbg.finish() # Finish current function
dbg.interrupt() # Stop the execution of your process
dbg.wait() # Wait until you have control of gdb
```

In the cases where you have to interact with the process before reaching the address you want you can use wait=False.

```py
...
dbg.breakpoint("main+0x12", temporary=True)
done = dbg.continue_until("main+0x43", wait=False)
dbg.p.recvline()
dbg.p.sendline(b"4")
# Here the script will wait until you reach the offset 0x43 from main while gdb will break at offset 0x12 to let you analyse the process manually in gdb
done.wait()
...
```

**Warning**  
* `finish` can only work if the stack frame hasn't been corrupted. With libdebug it will fail if the function doesn't use the base pointer.

If the function modifies itself you may find yourself unable to set breakpoints where you want. To analyse these function we can run them step by step

```py
def MyCallback(dbg):
    if dbg.next_inst.mnemonic == "int3":
        dbg.step()
        dbg.signal("SIGINT")
    print(dbg.next_inst.toString())

dbg.step_until_ret(MyCallback)
```

In this example at each step the callback will be executed decrypting the next function chunk by chunk and logging the instructions. See [this example](./examples/debug_self_modifying_function.py) for more details solving a real challenge.

You could also use `dbg.step_until_address(<address>, <callback=None>)` if you just want to execute a limited area of code or `dbg.step_until_condition(<check>)` if you are not sure where to stop.  

## Breakpoints

Breakpoints have three main features:
* if the address is smaller than the size of the binary the address will immediately be interpreted as relative for PIE binaries.
* you can use a symbol name instead of an address such as `"main"` or `"main+0x12"` (so far only supported for binary and libc).
* you can set callbacks to be executed when the breakpoint is reach and may choose to let the process continue after the execution.
    * If multiple callbacks are set on the same address they will be executed in a LIFO order.

The callback is a function that takes the debugger as parameter and returns a boolean to tell gdb if it should stop or not.
The callbacks shouldn't be limited in what you can code. If you find problems raise an issue.
If you want to pass data from your callback function to your exploit you can use pointers (lists, dictionaries or queues)

**Note**  
Setting a breakpoint requires the process to be interrupted.

```py
from gdb_plus import *
from queue import Queue

# I let the process run in this example to reinforce the need for the interrupt later
gdbinit = """
handle SIGALRM nopass
"""

dbg = Debugger("./challenge", script=gdbinit).remote("leet.pwn.com", 31337)
pointer = Queue()

# step over an hypothetical call to a function, overwrite the return value and save it in a queue
def MyCallback(dbg):
    dbg.next()
    log.info(f"I tried to return {dbg.rax}")
    pointer.put(dbg.rax)
    dbg.rax = 0
    # Return False to let the process run after executing the callback
    return False

def SecondCallback(dbg):
    log.info("now you can play around with gdb")
    log.info("once you are done execute continue in gdb and your script will resume once we reach main+0x534")
    # Return True to interrupt the process
    return True

# You can not set a breakpoint while the process is running
dbg.breakpoint("main+0x42", callback=MyCallback, temporary = True)
dbg.breakpoint("main+0x124", callback=SecondCallback)
dbg.continue_until("main+0x534")

# Read the data set by the breakpoint
print(pointer_to_secret.get())
dbg.delete_breakpoint("main+0x124")
```

**Warning**
You can script anything inside your callbacks, but be careful not to break the execution flow of your script. A putting a callback with `finish()` inside a function you are stepping over with `ni()` may cause problems. The alternative would be to set a second callback on the return_pointer of your function.  

```py
from gdb_plus import *
from queue import Queue

# I let the process run in this example to reinforce the need for the interrupt later
gdbinit = """
handle SIGALRM nopass
"""

dbg = Debugger("./challenge", script=gdbinit).remote("leet.pwn.com", 31337)

# Does work, but you may lose control of your script if you try to step over a call to waitpid
def dangerous_callback(dbg):
    status = dbg.args[1]
    dbg.finish()
    log.info(f"Child stopped with status : {hex(u32(dbg.read(status, 4)))}")
    return False

def safe_callback(dbg):
    status = dbg.args[1]
    def second_callback(dbg):
        log.info(f"Child stopped with status : {hex(u32(dbg.read(status, 4)))}")
        return False
    dbg.b(dbg.return_pointer, callback=second_callback, temporary=True)
    return False

dbg.b("waitpid", callback=safe_callback)
```

You can allocate chunks on the heap (or the bss if you don't have the libc), write and read in the ram and read the canary from anywhere.

```py
pointer = dbg.alloc(8)
dbg.write(pointer, p64(0xdeadbeef))
secret = dbg.read(dbg.elf.symbols["secret"], 0x10)
canary = dbg.canary
```

**Note**  
While you can access the registers only when the process is at a stop, remember that you can read and write on the memory at any time

We can also use capstone to know what is the next instruction that will be executed
```py
print(dbg.next_inst.toString()) # "mov rax, r12"
print(dbg.next_inst.mnemonic)   # "mov"
```

## Fork
You can set the debugger to spwn a new instance of gdb every time the process calls fork with `dbg.set_split_on_fork()`. The child will stop as soon as the process is created by fork, but will wait for the debugger to stop before creating the new object. To allow gdb to attach to the second process though you need to set the ptrace scope to 0 (`$sudo nano /etc/sysctl.d/10-ptrace.conf`).

```py
dbg = Debugger("http_server").set_split_on_fork()
done = dbg.continue_until(0x40233)
dbg.p.sendline("input")
done.wait()
# Now that the process stopped at address 0x40233 a new debugger will attach to the child
pid_child = dbg.wait_split()

# all children have their debugger saved in dbg.children and can be accessed by the pid
child = dbg.children[pid_child]
```

If the program traces its child to make sure you aren't debugging it or to unpack a region of code, you should be able to emulate the calls to ptrace. 

```py
child.emulate_ptrace_slave(dbg)
dbg.emulate_ptrace_master(child)
```

This will interrupt the process at every call to waitpid for the master and SIGSTOP or INT3 for the child. You have to handle yourself when to let each one of them continue while you debug them. To help you a bit we print "Slave can continue" every time the tracer tries to send a continue to the tracee

**Warning**
* If the tracee stopped with a SIGSTOP gdb may bug a bit and you may need `force=True` to make it continue correctly
* pwndbg can not handle multi-process applications and this section is only possible in native gdb or with GEF
* Handling multiple processes in the same debugger instead of splitting them may cause problems with the waits

## Call functions

If you want to test the effects of a specific function you can directly call it with the parameters you want

```py
pointer = dbg.alloc(100)
# Initialize data
dbg.write(pointer, bytes([i for i in range(100)]))
dbg.call(dbg.p.symbols["obfuscated_pbox"], [pointer, "user_1", 1])
dbg.read(pointer, 100)
```

See [this example](./examples/black_box_analysis_of_function.py) for more details

**Note**  
You can pass parameters as strings or byte_arrays. By default they will be saved on the heap with a null terminator in the case of a string. If you can't use the heap set `heap=False`

**Warning**  
If the stack frame has been corrupted finish() may not work. If this is the case set last address of your function in `call(..., end_pointer= ...)`.

## Ltrace, Ftrace and one day strace too.
ltrace is a useful program to get an idea of what your process is doing, but unfortunately it can not work if the process traces itself. Since we can emulate ptrace we can also offer an equivalent to ltrace that works even in that case. 

```py
from gdb_plus import *
dbg = Debugger(...)
# dbg.emulate_ptrace() # If needed
dbg.set_ltrace()
...
```

Adding set_ltrace() to your script will make it print all the library functions called by the process during the execution

If you only want to analyze a specific section of the binary you can also enable it for just that part.

```py
from gdb_plus import *
dbg = Debugger(...)
dbg.until(target_function)
dbg.set_ltrace()
dbg.finish()
dbg.disable_ltrace()
```

This case would only log the functions called during the execution of the target function.

Similar to ltrace that logs the library functions using gdb allows us to also define an ftrace function that would log all functions from the binary.

Since some functions may be recursive or not use the return instruction at the end of the function, calling finish on each function to also log the return value may break the debugger. In that case add the argument `no_return = True` to the call to `set_ftrace()`.

```py
from gdb_plus import *
dbg = Debugger(...)
dbg.set_ftrace() # dbg.set_ftrace(no_return = True)
dbg.c()
```

Tracing some basic function may be just a waste of time since the debugger has to stop every time they are called, so to improve the performances you can set the parameter `exclude` with the functions you don't want to break onto.

```py
from gdb_plus import *
dbg = Debugger(...)
dbg.set_ltrace(exclude=["malloc", "free", "strlen"])
dbg.set_ftrace(exclude=["FUN_126a", "FUN_13f1"])
dbg.c()
```

## Libdebug
By default GDB+ uses a gdbserver to debug the process. This is very useful when you also have to check manually gdb while you are writing a script, but can be very slow. For this reason we now support libdebug (from version >= 0.4) as an alternative debugger. It is lacking a lot of features but can do the job for most tasks and it can be 50 times faster. 
**NOTE**
libdebug has been refactored in october 2023. The new version doesn't allow yet the same control over events breaking a lot of features. We are therefore using the legacy version for now.

The debugger will always start with dbg, but you can switch back and forth

```py
dbg = Debugger(<binary>)
# switch to libdebug
dbg.migrate(libdebug=True)
# switch to gdb
dbg.migrate(gdb=True)
```

To access properties of libdebug that haven't been wrapped you can simply use `dbg.libdebug` as you would with `dbg.gdb`.

When you switch the breakpoints and callbacks will be preserved except for those needed to emulate ptrace. Please migrate to libdebug before setting the emulator up or disable it and set it up again right after.

Since libdebug_legacy isn't on PyPI yet we could't include it in the dependencies. 
You can install it manually:
`pip3 install git+https://github.com/Angelo942/libdebug.git`

## QEMU
GDB+ can debug processes running under QEMU. The current supported architectures are arm and riscv, both 32 and 64 bits.

The problem running in qemu is that the base address may be off, we can't identify when the process forks and we can't attach to a running process. This limits the features we can use, but the rest is working fine.

If your binary requires system libraries, look at the (instructions)[https://docs.pwntools.com/en/stable/qemu.html#telling-qemu-where-libraries-are] from pwntools. The main idea will be to download the libraries for cross compilation `sudo apt-get install libc6-<arch>-cross` and then copy them to QEMU `sudo ln -s /usr/<arch>-linux-gnu /etc/qemu-binfmt/<arch>`.

**Note**
* don't forget to install qemu and gdb-multiarch. `sudo apt install qemu-user gdb-multiarch`
* set context.arch == ... at the beginning of your script to make sure you are debugging your binary and not QEMU itself
* pwndbg may be better than GEF when using qemu.

# TODO
* Distinguish between process running and dead
* Improve ptrace emulation
    * handle waitpid(-1) with multiple slaves
    * emulate waitid too
* support multithread applications
* catch sigsegv as an exit instead of user interaction
* enable signal() with libdebug
* migrate to new version of libdebug
* force parent or child to stop tracing
* wrap follow-child
* specify relative addresses
* hide internal breakpoints also from gdb
* implement strace
* allow access to float registers or aliases
* write a decent documentation
