# I just need the elf to know if I should use eip or rip... I may just do it this way if I don't have the binary
# Redundant with context. May be still used for path and address, but I would remove it.

from pwn import ELF, context, log, unpack

# Right now it's only an ELF, but we can consider extending it to PE for windows one day
# isinstance(obj, ELF) will accept bot EXE and ELF
class EXE(ELF):
    def __init__(self, path, address=None, end_address=None, **kwargs):
        if isinstance(path, ELF):
            self.__dict__ = path.__dict__.copy()
            self.__class__ = EXE
        else:
            super().__init__(path, **kwargs)
        self.name = self.path.split("/")[-1]
        if address is not None: # pwntools already has an assumption for the initial address
            self.address = address
        self.end_address = end_address
        self.size = len(self.data)

    @ELF.address.setter
    def address(self, address):
        if self.address != 0 and self.address != address:
            log.warn("The base address of %s is not the one expected! Expected: %s. Received: %s", self.name, hex(self.address), hex(address))

        if address % 0x1000:
            log.warn("The address %s is not a multiple of the page size 0x1000. Are you sure this is your base address ?", hex(address))

        ELF.address.fset(self, address)

    # NOTE: What is the point of end_address = None if we set range to 0 and not None ? [05/02/25]
    # NOTE: We could set end_address to 0, but then we would have to worry about when address is set manually, but not end_address ? Not really I would say... [05/02/25]
    @property
    def range(self):
        if self.end_address is None:
            return 0
        return self.end_address - self.address

    def __contains__(self, value):
        if self.end_address is None:
            log.warn(f"I don't know which one is the last page of {self.name}. Please set end_address!")
            return False

        return self.address < value < self.end_address

# This is not guaranteed
# Debuggging qemu-mips64 find both a different loader than expected because of a symlink and more libraries than expected.
# TODO handle corrupted headers [11/10/26]
def enum_libs(file):
    """
    Find which libraries will be used by an executable without having to run it.
    """
    if file.statically_linked:
        return []

    # loader = None
    # for seg in file.iter_segments():
    #     if seg.header.p_type == "PT_INTERP":
    #         # this helper gives you the null-terminated interpreter path
    #         loader = seg.get_interp_name().rstrip('\x00')
    #         break
    # if loader is None:
    #     log.warn("can not find loader!")
    #     return []

    # libs = [Path(loader).name]
    libs = []

    # Get the .dynamic section (holds dynamic table entries)
    dynamic_section = file.get_section_by_name('.dynamic')
    if dynamic_section is None:
        print("No .dynamic section found. Section header may be corrupted")
        return []
    data = dynamic_section.data()

    # Get the .dynstr section (holds dynamic strings)
    dynstr_section = file.get_section_by_name('.dynstr')
    if dynstr_section is None:
        print("No .dynstr section found!")
        return []
    dynstr_data = dynstr_section.data()

    # Iterate over the dynamic table entries
    for i in range(0, len(data), context.bytes * 2):
        packed_tag, packed_val = data[i:i+context.bytes], data[i+context.bytes:i+context.bytes*2]
        if len(packed_val) < context.bytes:
            break
        tag, val = unpack(packed_tag), unpack(packed_val)
        # DT_NULL (tag 0) marks the end of the table
        if tag == 0:
            break
        # DT_NEEDED (tag 1) entries indicate required libraries
        if tag == 1:
            # 'val' is the offset into the .dynstr section for the library name
            end = dynstr_data.find(b'\x00', val)
            lib_name = dynstr_data[val:end].decode('utf-8')
            libs.append(lib_name)

    return libs
