from gdb_plus import *
from gdb_plus.extra.setup_clang import load_clang, clang
import copy
import struct
import re

# Mapping from Clang TypeKind to Python types
# Would be nice to handle signed values, but too complex for now
_KIND_TO_PY = {
    clang.cindex.TypeKind.BOOL:        bool,
    clang.cindex.TypeKind.CHAR_U:      int,    # unsigned char
    clang.cindex.TypeKind.UCHAR:       int,
    clang.cindex.TypeKind.CHAR_S:      bytes,  # signed char → treat as raw byte
    clang.cindex.TypeKind.SCHAR:       bytes,
    clang.cindex.TypeKind.CHAR16:      bytes,
    clang.cindex.TypeKind.CHAR32:      bytes,
    clang.cindex.TypeKind.UINT:        int,
    clang.cindex.TypeKind.USHORT:      int,
    clang.cindex.TypeKind.ULONG:       int,
    clang.cindex.TypeKind.ULONGLONG:   int,
    clang.cindex.TypeKind.INT:         int,
    clang.cindex.TypeKind.SHORT:       int,
    clang.cindex.TypeKind.LONG:        int,
    clang.cindex.TypeKind.LONGLONG:    int,
    clang.cindex.TypeKind.FLOAT:       float,
    clang.cindex.TypeKind.DOUBLE:      float,
    clang.cindex.TypeKind.LONGDOUBLE:  float,
}

def parse_header_file(name: str, code: str) -> dict:
    load_clang()

    # Create Clang index and parse the in-memory code
    index = clang.cindex.Index.create()
    tu = index.parse(
        path='struct.h',
        args=['-std=c11', '-fpack-struct'],
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

    # Check diagnostics for undeclared identifiers
    for diag in tu.diagnostics:
        msg = diag.spelling
        if diag.severity >= clang.cindex.Diagnostic.Error:
            raise RuntimeError(f"Clang parse error: {msg}")
    
    sizes = {}
    py_types = {}
    # Find the typedef for FILE and output its field offsets
    for cursor in tu.cursor.get_children():
        if cursor.kind == clang.cindex.CursorKind.TYPEDEF_DECL and cursor.spelling == name:
            struct_decl = cursor.underlying_typedef_type.get_declaration()
            struct_type = cursor.underlying_typedef_type
            size = struct_type.get_size()
            old_field = None
            old_offset = 0
            for field in struct_decl.get_children():
                if field.kind != clang.cindex.CursorKind.FIELD_DECL:
                    continue

                offset_bits = struct_type.get_offset(field.spelling)
                offset_bytes = offset_bits // 8
                if old_field is not None:
                    sizes[old_field] = offset_bytes - old_offset

                # Handle fixed-size char arrays → bytes
                if field.type.kind == clang.cindex.TypeKind.CONSTANTARRAY:
                    # print(f"{field.spelling} is an array ", end="")
                    elem = field.type.get_array_element_type()
                    if elem.kind in (clang.cindex.TypeKind.RECORD, clang.cindex.TypeKind.ELABORATED):
                        decl = elem.get_declaration()
                        # print(f"of {decl.spelling=}")
                        py_types[field.spelling] = [decl.spelling, field.type.get_array_size()]
                    elif _KIND_TO_PY.get(elem.kind, None) is bytes:
                        # print("of bytes")
                        py_types[field.spelling] = bytes
                    else:
                        # fallback for other arrays
                        base = _KIND_TO_PY[elem.kind]
                        # print(f"of {base=}")
                        py_types[field.spelling] = [base, field.type.get_array_size()]
                elif field.type.kind == clang.cindex.TypeKind.POINTER:
                    # print(f"{field.spelling} is an pointer ", end="")
                    pointee = field.type.get_pointee()
                    if pointee.kind in (clang.cindex.TypeKind.RECORD, clang.cindex.TypeKind.ELABORATED):
                        decl = pointee.get_declaration()
                        type = decl.spelling
                    else:
                        type = _KIND_TO_PY.get(pointee.kind, pointee.kind)
                    # print(f"to {type}")
                    py_types[field.spelling] = Array([type])
                else:
                    # print(f"{field.spelling} is {field.type.kind}")
                    py_types[field.spelling] = _KIND_TO_PY.get(field.type.kind, field.type.kind)

                old_field = field.spelling
                old_offset = offset_bytes

            sizes[old_field] = size - old_offset
            break
    else:
        log.error(f"can not find {name} in the given structure: \n{code}")

    return sizes, py_types

# Could be interesting in gdb_plus.py a method to recursively read and write structures in memory
class Structure:
    def __init__(self, name: str, header: [str, dict], *, address: int = 0, types: dict = None):
        self._name = name
        self._symbols = {}
        self._content = {}
        self._address = address
        
        if isinstance(header, str):
            self._sizes, self._types = parse_header_file(name, header)
            self._header = header
        elif isinstance(header, dict):
            self._sizes = header # We assume that sizes never changes, so we can copy only the reference
            self._types = types
        else:
            log.error("header must be string or dictionary!")

        self._total_size = 0
        for variable, size in self._sizes.items():
            if variable == "address":
                log.error("Structure can not have reserved attribute \"address\"!")
            self._symbols[variable] = self._total_size
            self._total_size += size

        self.address = address

    def load(self, raw_data: bytes, *, expand = False):
        # Maybe we should just give a warning if len(raw_data) > len(self) and still continue
        assert len(raw_data) == len(self), f"{self._name} expected {len(self)} bytes, but got {len(raw_data)}"

        counter = 0
        for variable, size in self._sizes.items():
            self._content[variable] = unpack(raw_data[counter:counter+size], size*8)
            counter += size

        if expand:
            self.expand()

        return self

    def expand(self):
        assert self._types is not None, "Please, give me a header file to know what types are used."
        
        def parse(data, type, size):
            if type is int:
                return data
            elif isinstance(type, str):
                if isinstance(data, int): data = data.to_bytes(size, "little")
                return Structure(type, self._header).load(data, expand=True) # All types should be defined to compile anyway, so when would this fail ?
            elif type is bytes:
                return data.to_bytes(size, "little")
            elif type is float:
                if isinstance(data, int): data = data.to_bytes(size, "little")
                if size == 4:
                    return struct.unpack('f', data)[0]
                elif size == 8:
                    return struct.unpack('d', data)[0]
                else:
                    log.warn_once("Unsupported float byte size expanding data. Supported sizes: 4, 8.")
                    data = int.from_bytes(data, "little")
                    return data
            # We have no information on how to read, and how many elements, so we can't handle this case
            elif isinstance(type, Array):
                return Array([], address=data)
            # The trouble here is to split properly the data in each chunk
            elif isinstance(type, list):
                result = []
                type, n_elements = type[:]
                if isinstance(data, int): data = data.to_bytes(size, "little")
                length = size // n_elements
                for i in range(n_elements):
                    result.append(parse(data[i*length:(i+1)*length], type, length))
                return result
            else:
                raise ValueError(f"What type is {type} ?")

        for variable, type in self._types.items():
            self._content[variable] = parse(getattr(self, variable), type, self._sizes[variable])


    def export(self):
        def pack_float(value: float, num_bytes: int) -> bytes:
            if num_bytes == 4:
                return struct.pack('f', value)
            elif num_bytes == 8:
                return struct.pack('d', value)
            else:
                raise ValueError("Unsupported float byte size. Supported sizes: 4, 8.")

        def parse(obj, size, name=None):
            if isinstance(obj, Element):
                return parse(obj.address, size)

            if isinstance(obj, str):
                obj = obj.encode()
            if isinstance(obj, bytes):
                obj = int.from_bytes(obj, "little")
            if isinstance(obj, int):
                return pack(obj, size*8)
            elif isinstance(obj, float):
                return pack_float(obj, size)
            elif isinstance(obj, list):
                if len(obj) > size:
                    log.error(f"{obj} can not fit in {size} bytes. If {name} is a pointer to your list, please assign it with struct.{name} = Array([...], address=struct.{name})")
                return b"".join([parse(item, size//len(obj)) for item in obj])
            elif isinstance(obj, Structure):
                # Would be nice to detect if it should be a pointer and then pack obj.address instead. Could we do it from the header file ? [21/06/25]
                # If things are parsed properly we could do a check obj.address == self._symbols[name] to know if it's a pointer or not
                if obj.address  and self.address:
                    return obj.export() if obj.address == self._symbols[name] else parse(obj.address, size)

                return obj.export() if len(obj) == size else parse(obj.address, size) # We could check that size is a pointer size...
            else:
                raise ValueError(f"Unsupported type for {name}")

        structure = b''
        for name, size in self._sizes.items():
            parsed = parse(getattr(self, name), size, name)
            if len(parsed) != size:
                log.warn(f"something went wrong exporting {name}")
            structure += parsed
        if len(structure) != len(self):
            log.warn(f"something went wrong exporting {self._name}")
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
            structure.append(f"{hex(self._symbols[name])}: {name} -> {hex(getattr(self, name)) if isinstance(getattr(self, name), int) else getattr(self, name)}")
        return "{\n"+ "\n".join(structure)+"\n}"

    def __len__(self):
        return self._total_size
    
    def __bytes__(self):
        return self.export()

    def __getattr__(self, name):
        if self.__dict__.get('_sizes') is not None and name in self._sizes:
            return self._content.get(name, 0)
        else:
            return self.__getattribute__(name)

    # Make Array and String as invisible as possible
    def __setattr__(self, name, value):
        if self.__dict__.get('_types') is not None and name in self._sizes:
            # If we are overwriting a pointer of which we know the address
            if self._types is not None and isinstance(self._types[name], Array) and not isinstance(value, Element):
                # The structure has been expanded but we haven't assigned a value to the Array/String yet
                if isinstance(getattr(self, name), Element) and len(getattr(self, name)) == 0:
                    address = getattr(self, name).address
                elif isinstance(getattr(self, name), int):
                    address = getattr(self, name)
                else:
                    self._content[name] = value
                    return
                
                if isinstance(value, str):
                    value = value.encode()
                if isinstance(value, list):
                    self._content[name] = Array(value, address=address)
                elif isinstance(value, bytes):
                    self._content[name] = String(value, address=address)
                else: # We could maybe first check that the type matches or something...
                    self._content[name] = Array([value], address=address)
            else:
                self._content[name] = value
        else:
            super().__setattr__(name, value)

    def __dir__(self):
        return object.__dir__(self) + list(self._symbols)

    def __eq__(self, other):
        if isinstance(other, Structure):
            return bytes(self) == bytes(other)
        elif isinstance(other, bytes):
            return bytes(self) == other
        return NotImplemented

    # 6x faster than doing deepcopy
    def copy(self):
        # return copy.deepcopy(self)
        
        new_obj = copy.copy(self)
        counter = 0
        new_obj._content = {}
        new_obj._symbols = copy.copy(self._symbols) # This should be faster than reconstructing it by computing values
        return new_obj

        # return Structure(self._name, self._sizes, types=self._types) # This as the same time as copy.copy, but looses eventual additional methods we add...

class Element:
    def __init__(self, address=0):
        self.address = address

    def __repr__(self):
        return f"{hex(self.address)} -> {super().__repr__()}"

# I would want to call it vector, but it has a specific meaning
# Can we treat an Array with only one element in a different way ? [26/06/25]
class Array(Element, list):
    def __init__(self, *args, address=0):
        Element.__init__(self, address)
        list.__init__(self, *args)

    def export(self):
        def pack_float(value: float, num_bytes: int) -> bytes:
            if num_bytes == 4:
                return struct.pack('f', value)
            elif num_bytes == 8:
                return struct.pack('d', value)
            else:
                raise ValueError("Unsupported float byte size. Supported sizes: 4, 8.")

        def parse(obj, size, name=None):
            if isinstance(obj, Element):
                return parse(obj.address, size)

            if isinstance(obj, str):
                obj = obj.encode()
            if isinstance(obj, bytes):
                obj = int.from_bytes(obj, "little")
            if isinstance(obj, int):
                return pack(obj, size*8)
            elif isinstance(obj, float):
                return pack_float(obj, size)
            elif isinstance(obj, list):
                if len(obj) > size:
                    log.error(f"{obj} can not fit in {size} bytes. If {name} is a pointer to your list, please assign it with struct.{name} = Array([...], address=struct.{name})")
                return b"".join([parse(item, size//len(obj)) for item in obj])
            elif isinstance(obj, Structure):
                # Would be nice to detect if it should be a pointer and then pack obj.address instead. Could we do it from the header file ? [21/06/25]
                # If things are parsed properly we could do a check obj.address == self._symbols[name] to know if it's a pointer or not
                if obj.address  and self.address:
                    return obj.export() if obj.address == self._symbols[name] else parse(obj.address, size)

                return obj.export() if len(obj) == size else parse(obj.address, size) # We could check that size is a pointer size...
            else:
                raise ValueError(f"Unsupported type for {self._name}.{name}")

        structure = b''
        for name, size in self._sizes.items():
            parsed = parse(getattr(self, name), size, name)
            if len(parsed) != size:
                log.warn(f"something went wrong exporting {name}")
            structure += parsed
        if len(structure) != len(self):
            log.warn(f"something went wrong exporting {self._name}")
        return structure

    def __eq__(self, other):
        # Must be equal even with different addresses. We just check the content
        if isinstance(other, list):
            return list(self) == list(other)
        elif isinstance(other, int):
            return self.address == other
        return NotImplemented

class String(Element, bytes):
    def __new__(cls, content=b"", address=0):
        # bytes is immutable, so we override __new__ not __init__
        obj = bytes.__new__(cls, content)
        Element.__init__(obj, address)
        return obj

    def __init__(self, content=b"", address=0):
        # now only address goes into Element.__init__
        Element.__init__(self, address)

    def export(self):
        return bytes(self)

    def __eq__(self, other):
        # Must be equal even with different addresses. We just check the content
        if isinstance(other, bytes):
            return bytes(self) == bytes(other)
        elif isinstance(other, int):
            return self.address == other
        return NotImplemented