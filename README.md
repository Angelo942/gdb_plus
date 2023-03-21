# GDB+
*Python library to automate gdb debugging* 

GDB+ is a wrapper around gdb powered by pwntools. The goal is automate your interactions with gdb and add some extra features.

## Main features

* Include a python function as callback when you set a breakpoint.
* Read the canary instead of bruteforcing it every time you need it while testing your exploit.
* Test a specific function of a binary with the parameters you want at any time.
* Log the code of a self modifying function.
* Backup parts of your memory and restore it during future executions.
* Don't waste time commenting your code. The arguments `NOPTRACE` and `REMOTE` make the exploit skip any action related to gdb.

## Installation

```
pip3 install gdb_plus
```

**Warning for pwndbg users:**  
Previous bugs in Pwndbg used to break the api for python. While most of GDB+ should work with the current version of pwndbg [19/12/2022], pwndbg can not debug both processes after a fork.
you are strongly advised to use [GEF](https://github.com/hugsy/gef) instead.

## Debugging

You can debug a program using the path to the binary.   
If you really have to you can also use a process or even just his pid. 
For pwn challenges set the remote address with `Debugger().remote(<host>, <port>)` and use the argument `REMOTE` once you want to exploit the server

```py
from gdb_plus import *

gdbinit = """
handle SIGALRM nopass
continue
"""

dbg = Debugger("./rev_challenge", script=gdbinit, aslr=False)
dbg = Debugger("./pwn_challenge", script=gdbinit).remote("10.10.0.1", 1337)


p = process("./challenge", aslr=False)
dbg = Debugger(p, script=gdbinit)

#pidof process : 3134
dbg = Debugger(3134, script=gdbinit, binary="./challenge")
```

Calling your script with pwntools arguments `NOPTRACE` or `REMOTE` will allow you to disable all actions related to gdb and test your exploit localy or attack the remote target without having to comment anything. If you want a finer control you can use `ìf dbg.debugging` to discriminate the code that should be executed when gdb is opened or not.

**Note**  
Debugger can also take as parameter a dictionary for the environment variables. You CAN use it to preload libraries, but if you want to do it for the libc I would advise to **patch the rpath** of the binary instead (if you don't know how take a look at [spwn](https://github.com/MarcoMarce) or [pwninit](https://github.com/io12/pwninit). This will prevent problems when running `system("/bin/sh")` that will fail due to LD_PRELOAD and may hide other problems in your exploit.

**Warning**  
Old versions of gdbserver (< 11.0.50) have problems launching 32bit binaries. If you see a crash trying to find the canary use `from_start=False` as parameter for the debugger. This will launch the process and then attach to it once the memory has been correctly mapped

## Control Flow

The main actions for gdb are already wrapped in individual methods. For all commands not present you can reconstruct them by calling `dbg.execute(<command>)` as if you where using gdb.

```py
dbg.step() # Single instruction (will enter function calls)
dbg.next() # Next instruction (will jump over function calls)
dbg.cont() # Continue execution
dbg.finish() # Finish current function
dbg.interrupt() # Stop the execution of your process
dbg.wait() # Wait untill you have control of gdb
```

**Warning**  
* `finish` can only work if your function has a `leave; ret;` at the end
* `wait` can take as parameter a timeout. Use it if you aren't sure gdb has already stoped to avoid waiting forever.
* `ìnterrupt` expects that the process is currently running. If you aren't sure it will be the case use `interrupt(wait=False)`

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

You could also use `dbg.step_until_address(<address>, <callback=None>)` if you just want to execute a limited area of code.  

## Breakpoints

Breakpoints have two main features:
* if the address is smaller than 0x10000 the address will immediately be interpreted as relative for PIE binaries 
* you can set callbacks and don't have the breakpoint interrupt the process to run them

The callback is a function that takes the debugger as parameter and returns a boolean to tell gdb if it should stop or not. Inside you can do anything you want with the memory
If you want to pass data from your callback function to your exploit you can use pointers (lists, dictionaries or queues)

**Note**  
Setting a breakpoint requires the process to be interrupted.

```py
from gdb_plus import *
from queue import Queue

# I let the process run in this example to reinforce the need for the interrupt later
gdbinit = """
handle SIGALRM nopass
continue
"""

dbg = Debugger("./challenge", script=gdbinit).remote("leet.pwn.com", 31337)
pointer_to_secret = Queue()

def MyCallback(dbg):
    pointer_to_secret.put(dbg.rdx)
    return False

# You have to interrupt the execution if you want a callback
dbg.interrupt()
dbg.breakpoint("encrypt") # Break on function "encrypt"
dbg.breakpoint(0xdead, callback=MyCallback)
dbg.cont()

dbg.wait()
# Read the data set by the breakpoint
print(pointer_to_secret.get())
# You can disable individual breakpoints 
dbg.breakpoints[hex(dbg.base_elf + 0xdead)].enabled = False # To access a breakpoint you will need the full address
dbg.breakpoints["encrypt"].enabled = False # And the name if you didn't set it with an address
```

Currently you can set the breakpoint to permanent or temporary. Permanent ones get saved in `dbg.breakpoints[hex(absolute_address)]`, temporary ones aren't saved and get disabled automatically when hit for the first time. 

**Warning**
"*When hit*". If the return value of a callback is False the breakpoint won't be hit. This means that a temporary breakpoint won't be removed in this situation and the callback may end up being called multiple times if you are in a loop.

## Memory access

All registers are accessible as properties

```py
dbg.rax = 0xdeadbeefdeadbeef
dbg.eax = 0xfafafafa
dbg.ax  = 0xbabe
dbg.ah = 0x90
assert dbg.rax == 0xdeadbeeffafa90be
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

Pwntools let you access the address where each library is loaded with `p.libs()[<path_to_library>]`
We have two wrapper for the main ones:
* `dbg.base_elf`
* `dbg.base_libc`

from gdb_plus >= 5.4.0 dbg.elf.address is already set to the correct address even with ASLR on, so you may need dbg.base_elf only if you debug a process for wich you don't have the binary

We can also use capstone to know what is the next instruction that will be executed
```py
print(dbg.next_inst.toString()) # "mov rax, r12"
print(dbg.next_inst.mnemonic)   # "mov"
```

## Black box

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
You may want to be careful with breakpoints inside the function called. If you don't set any the state of you process will be identical after the execution except for data writen on the stack (which shouldn't influence the future) and the bss (which you may want to correct if needed on a case by case). If you put a breakpoint you will have to handle yourself the execution from your breakpoint onward.  
Another option would be to pass a pointer to the return instruction, it will block you python script untill you reach that specific point, so you will have to work manualy from gdb for that part.

## Alternatives
If something can be done with gdb it should be easily programable with gdb_plus, but you may find it slow as hell for some uses. This tool is meant to help debugging during challenges, if you only want to automate exploit developement you may prefere something like [libdebug](https://github.com/JinBlack/libdebug) which doesn't has to communicate with gdb for each command.