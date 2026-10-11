## SHELLCODES
# test: nop; jmp test / nop; b 0x0
shellcode_sleep = {
    "amd64": b"\x90\xeb\xfe",
    "i386": b"\x90\xeb\xfe",
    "aarch64": b'\x1f\x20\x03\xd5\x00\x00\x00\x14',
    "arm": b'\x00\xf0\x20\xe3\xfe\xff\xff\xea',
}
# syscall / int 0x80 / svc #0
shellcode_syscall = {
    "amd64": b"\x0f\x05",
    "i386": b"\xcd\x80",
    "aarch64": b'\x01\x00\x00\xd4',
    "arm": b'\x00\x00\x00\xef',
    "riscv32": b's\x00\x00\x00',
    "riscv64": b's\x00\x00\x00',
    "mips": b'\x0c\x00\x00\x00',
    "mips64": b'\x0c\x00\x00\x00',
}
# First register is where to save the syscall num
syscall_calling_convention = {
    "amd64": ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"],
    "i386": ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
    "aarch64": ["x8"]+[f"x{i}"for i in range(6)],
    "arm": ["r7"]+[f"r{i}"for i in range(7)],
    "riscv32": ["a7"]+[f"a{i}"for i in range(6)],
    "riscv64": ["a7"]+[f"a{i}"for i in range(6)],
    "mips": ["v0"] + [f"a{i}" for i in range(4)],
    "mips64": ["v0"] + [f"a{i}" for i in range(6)],
}
function_calling_convention = {
    "amd64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "i386": [],
    "aarch64": [f"x{i}"for i in range(8)],
    "arm": [f"r{i}"for i in range(4)],
    "riscv32": [f"a{i}"for i in range(8)],
    "riscv64": [f"a{i}"for i in range(8)],
    "mips": [f"a{i}" for i in range(4)],
    "mips64": [f"a{i}" for i in range(6)],
}
return_instruction = {
    "amd64": b"\xc3",
    "i386": b"\xc3",
    "aarch64": b'\xc0\x03_\xd6',
    "arm": b'\x1e\xff\x2f\xe1',
    "riscv32": b'g\x80\x00\x00',
    "riscv64": b'g\x80\x00\x00',
    "mips": b'\x08\x00\xe0\x03',
    "mips64": b'\x08\x00\xe0\x03',
}
nop = {
    "amd64": b"\x90",
    "i386": b"\x90",
    "aarch64": b'\x1f\x20\x03\xd5',
    "arm": b'\x00\xf0\x20\xe3',
    "riscv32": b'\x13\x00\x00\x00',
    "riscv64": b'\x13\x00\x00\x00',
    "mips": b'\x00\x00\x00\x00',
    "mips64": b'\x00\x00\x00\x00',
}
