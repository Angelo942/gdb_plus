GDB+ 6.3.0: Let's go faster
* Can use gdb or libdebug ad debugger
	- gdb can be used manually, but will be slower to script
	- libdebug has less fetures and more bugs
Notes:
* countinue_until doesn't run the program if you already are at the specified address and the parameter `loop` isn't passed `True`
* call() should only be used from outside the function you want to call