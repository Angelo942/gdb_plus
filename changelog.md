GDB+ 6.3.2: small improvements
* standardise how inferiors are handled
	- inferiors can be specified only to read and write memory. Split the debugger or use switch_inferior if you have to perform other actions.

GDB+ 6.3.1: hotfix libdebug
* Make libdebug optional since it can't be added as a dependency (thanks PyPI)

GDB+ 6.3.0: **Let's go faster**
* Can use gdb or libdebug ad debugger
	- gdb can be used manually, but will be slower to script
	- libdebug has less fetures and more bugs
Notes:
* countinue_until doesn't run the program if you already are at the specified address and the parameter `loop` isn't passed `True`
* call() should only be used from outside the function you want to call