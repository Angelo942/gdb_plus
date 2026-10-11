from dataclasses import dataclass

@dataclass
class Inner_Breakpoint:
    byte: bytes = None
    temporary: bool = False

# I need a way to no if the process stopped due to my debugger or an action done manually
class Breakpoint:
    def __init__(self, breakpoint, address, callback = None, temporary = False, user_defined = True, hw = False):
        self.native_breakpoint = breakpoint
        self.address = address
        self.callback = callback
        self.temporary = temporary
        self.user_defined = user_defined
        self.hw = False
