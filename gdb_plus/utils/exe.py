# I just need the elf to know if I should use eip or rip... I may just do it this way if I don't have the binary
# Redundant with context. May be still used for path and address, but I would remove it.

from __future__ import annotations
from typing import TYPE_CHECKING
from pwn import ELF, log

if TYPE_CHECKING:
    from pathlib import Path

# Right now it's only an ELF, but we can consider extending it to PE for windows one day
# isinstance(obj, ELF) will accept bot EXE and ELF
# Shouldn't we set end address every time we have the base address ? [17/11/26]
class EXE(ELF):
    def __init__(self, path: ELF | str | Path, address: int | None = None, end_address: int | None = None, **kwargs: bool) -> None:
        if isinstance(path, ELF):
            self.__dict__ = path.__dict__.copy()
            self.__class__ = EXE
        else:
            super().__init__(path, **kwargs)
        self.name = self.path.split("/")[-1]
        self.size = len(self.data)
        self._end_address = end_address
        if address is not None: # pwntools already has an assumption for the initial address
            self.address = address

    @ELF.address.setter
    def address(self, address: int) -> None:
        if self.address != 0 and self.address != address:
            log.warn("The base address of %s is not the one expected! Expected: %s. Received: %s", self.name, hex(self.address), hex(address))

        if address % 0x1000:
            log.warn("The address %s is not a multiple of the page size 0x1000. Are you sure this is your base address ?", hex(address))

        ELF.address.fset(self, address)

    @property
    def mapped_size(self) -> int:
        """
        Size of the image once loaded: from the first page of the first PT_LOAD to the last page of the last one (.bss included).
        """
        if "_mapped_size" not in self.__dict__:
            page_size = 0x1000
            segments = [seg.header for seg in self.iter_segments_by_type("PT_LOAD")]
            if not segments: # Corrupted or stripped headers: the file size is the best we can do
                log.warn_once(f"{self.name} has no PT_LOAD segment. Using the file size as the mapped size")
                self._mapped_size = (self.size + page_size - 1) & ~(page_size - 1)
            else:
                low = min(h.p_vaddr for h in segments) & ~(page_size - 1)
                high = (max(h.p_vaddr + h.p_memsz for h in segments) + page_size - 1) & ~(page_size - 1)
                self._mapped_size = high - low
        return self._mapped_size

    @property
    def end_address(self) -> int:
        if self._end_address is not None:
            return self._end_address
        return self.address + self.mapped_size

    @end_address.setter
    def end_address(self, end_address: int | None) -> None:
        if end_address is not None and self.address and end_address != self.address + self.mapped_size:
            log.debug(f"[{self.name}] end address {hex(end_address)} differs from the one computed from the headers {hex(self.address + self.mapped_size)}")
        self._end_address = end_address

    def __contains__(self, value: int) -> bool:
        if self.end_address is None:
            log.warn(f"I don't know which one is the last page of {self.name}. Please set end_address!")
            return False

        return self.address <= value < self.end_address

# This is not guaranteed
# Debuggging qemu-mips64 find both a different loader than expected because of a symlink and more libraries than expected.
# TODO handle corrupted headers [11/10/26]
def enum_libs(file: ELF) -> list[str]:
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
    libs: list[str] = []

    # Get the .dynamic section (holds dynamic table entries)
    dynamic_section = file.get_section_by_name('.dynamic')
    if dynamic_section is None:
        print("No .dynamic section found. Section header may be corrupted")
        return []

    # Iterate over the dynamic table entries
    for tag in dynamic_section.iter_tags():
        # DT_NEEDED entries indicate required libraries
        if tag.entry.d_tag == "DT_NEEDED":
            libs.append(tag.needed)

    return libs
