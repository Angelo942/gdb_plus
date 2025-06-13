from gdb_plus import *
from gdb_plus.extra.setup_clang import load_clang, clang
import copy

class Element(int):
    def __new__(cls, value, address=0):
        obj = super().__new__(cls, value)
        obj.value = value
        obj.address = address
        return obj

    def __str__(self):
        return f"{hex(self.address)} -> {hex(self.value)}"

def parse_header_file(name: str, code: str) -> dict:
    load_clang()

    sizes = {}

    # Create Clang index and parse the in-memory code
    index = clang.cindex.Index.create()
    tu = index.parse(
        path='struct.h',
        args=['-std=c11'],
        unsaved_files=[('struct.h', code)],
        options=0
    )

    # Check for parsing errors and exit if any
    if tu.diagnostics:
        print("Errors parsing translation unit:")
        severity_map = {
            0: "Ignored",
            1: "Note",
            2: "Warning",
            3: "Error",
            4: "Fatal"
        }
        for diag in tu.diagnostics:
            severity = severity_map.get(diag.severity, "Unknown")
            print(f"  {severity}: {diag.spelling} (at {diag.location.file}:{diag.location.line})")
        raise Exception
    
    # Find the typedef for FILE and output its field offsets
    for cursor in tu.cursor.get_children():
        if cursor.kind == clang.cindex.CursorKind.TYPEDEF_DECL and cursor.spelling == name:
            struct_decl = cursor.underlying_typedef_type.get_declaration()
            struct_type = cursor.underlying_typedef_type
            size = struct_type.get_size()
            old_field = None
            old_offset = 0
            for field in struct_decl.get_children():
                if field.kind == clang.cindex.CursorKind.FIELD_DECL:
                    offset_bits = struct_type.get_offset(field.spelling)
                    offset_bytes = offset_bits // 8
                    if old_field is not None:
                        sizes[old_field] = offset_bytes - old_offset
                    old_field = field.spelling
                    old_offset = offset_bytes
            sizes[old_field] = size - old_offset
            break
    else:
        log.error(f"can not find {name} in the given structure: \n{code}")

    return sizes


class Structure:
    def __init__(self, name: str, header: [str, dict], *, address: int = 0):
        self.name = name
        self._symbols = {}
        self._content = {}
        self._address = 0
        
        if isinstance(header, str):
            self._sizes = parse_header_file(name, header)
        elif isinstance(header, dict):
            self._sizes = header # We assume that sizes never changes, so we can copy only the reference
        else:
            log.error("header must be string or dictionary!")

        self._total_size = 0
        for variable, size in self._sizes.items():
            self._symbols[variable] = self._total_size
            self._total_size += size

        self.address = address

    def load(self, raw_data: bytes):
        # Maybe we should just give a warning if len(raw_data) > len(self) and still continue
        assert len(raw_data) == len(self), f"{self.name} expected {len(self)} bytes, but got {len(raw_data)}"

        counter = 0
        for variable, size in self._sizes.items():
            self._content[variable] = unpack(raw_data[counter:counter+size], size*8)
            counter += size
        return self

    def export(self):
        structure = b''
        for name, val in self._content.items():
            structure += pack(val, self._sizes[name]*8)
        return structure

    @property
    def address(self):
        return self._address

    @property
    def symbols(self):
        return self._symbols
    
    @address.setter
    def address(self, value):
        for name in self._symbols:
            self._symbols[name] += value - self._address
        self._address = value

    def __repr__(self):
        structure=[]
        for name in self._symbols:
            structure.append(f"{hex(self._symbols[name])}: {name} -> {hex(self._content[name]) if isinstance(self._content[name], int) else self._content[name]}")
        return "{"+ "\n".join(structure)+"}"

    def __len__(self):
        return self._total_size
    
    def __bytes__(self):
        return self.export()

    def __getattr__(self, name):
        if self.__dict__.get('_content') and name in self._sizes:
            return self._content.get(name, 0)
        else:
            return self.__getattribute__(name)

    def __setattr__(self, name, value):
        if self.__dict__.get('_content') and name in self._sizes:
            self._content[name] = value
        else:
            super().__setattr__(name, value)

    def __dir__(self):
        return object.__dir__(self) + list(self._symbols)

    # 6x faster than doing deepcopy
    def copy(self):
        # return copy.deepcopy(self)
        
        new_obj = copy.copy(self)
        counter = 0
        new_obj._content = {}
        new_obj._symbols = copy.copy(self._symbols) # This should be faster than reconstructing it by computing values
        return new_obj

        # return Structure(self.name, self._sizes) # This as the same time as copy.copy, but looses eventual additional methods we add...