import io
import struct
from collections import OrderedDict

CHAR = 'c'
SIGNED_CHAR = 'b'
UCHAR = 'B'
BOOL = '?'
SHORT = 'h'
USHORT = 'H'
INT = 'i'
UINT = 'I'
LONG = 'l'
ULONG = 'L'
LONGLONG = 'q'
ULONGLONG = 'Q'
FLOAT = 'f'
DOUBLE = 'd'
VOIDPTR = 'P'


class CStruct(type):
    def __prepare__(self, name):
        # Little Hack :D
        # Before python 3.6(PEP 520), namespace is initialised as an empty dict,
        # but for our purpose we must use a ordered dict because we must preserve
        # attribute definition order!
        return OrderedDict()

    def __new__(mcs, name, bases, dct):
        __structure__ = {}
        fmt = str()

        # Fields
        for key, value in dct.items():
            if key.startswith("_") \
                    or key.startswith("__") \
                    or key.endswith("_") \
                    or key.endswith("__") \
                    or not isinstance(value, str):
                continue
            __structure__[key] = value
            fmt += value

        # Special property and methods
        dct["__bytes__"] = CStruct.to_bytes
        dct["__parse_endianness"] = CStruct.__parse_endianness
        dct["__structure__"] = __structure__
        dct["__size__"] = struct.calcsize(fmt)
        dct["pack"] = CStruct.pack
        dct["set_endianness"] = CStruct.set_endianness
        dct["unpack"] = CStruct.unpack
        dct["unpack_from_io"] = CStruct.unpack_from_io

        if "__endianness__" not in dct:
            dct["__endianness__"] = '@'

        ist = type.__new__(mcs, name, bases, dct)
        ist.__endianness__ = CStruct.__parse_endianness(ist, ist.__endianness__)
        return ist

    @staticmethod
    def to_bytes(cls):
        return bytes(cls.pack())

    @staticmethod
    def pack(cls, endianness=None):
        structure = getattr(cls, "__structure__")
        package = bytearray()
        endianness = CStruct.__parse_endianness(cls, endianness)
        for key, value in structure.items():
            fmt = endianness + value
            package += struct.pack(fmt, getattr(cls, key))
        return package

    @staticmethod
    def unpack_from_io(cls, stream: io.RawIOBase, endianness=None):
        cls.unpack(stream.read(cls.__size__), endianness)

    @staticmethod
    def set_endianness(cls, endianness):
        cls.__endianness__ = CStruct.__parse_endianness(cls, endianness)

    @staticmethod
    def __parse_endianness(cls, endianness=None):
        if endianness is None:
            return cls.__endianness__
        if endianness == "big":
            endianness = '>'
        elif endianness == "little":
            endianness = '<'
        elif endianness != '>' and endianness != '<' and endianness != '!' and endianness != '@':
            raise ValueError("invalid argument, endianness must be one of these: @, little(<), big(>, !)")
        return endianness

    @staticmethod
    def unpack(cls, data, endianness=None):
        structure = getattr(cls, "__structure__")
        cursor = 0
        endianness = CStruct.__parse_endianness(cls, endianness)
        for key in structure:
            fmt = endianness + structure[key]
            try:
                size = struct.calcsize(fmt)
                extr = struct.unpack(fmt, data[cursor:cursor + size])
                setattr(cls, key, extr[0])
                cursor += size
            except struct.error as err:
                raise struct.error("field %s: %s" % (key, err))


def unpack_type(dtype, data, endianness=None):
    if endianness is not None:
        dtype = endianness + dtype
    return struct.unpack(dtype, data)[0]


def sizeof(dtype):
    return struct.calcsize(dtype)
