import io

# *****************
# *  Fat Header   *
# *****************
# | Mach-O Header |
# *****************
# | Load Commands |
# *****************
# |     Data      |
# *****************

MACHO_UINT32 = 4
MACHO_CPUTYPE = 4
MACHO_CPUSTYPE = 4

MACHO_MAGIC32 = bytes([0xFE, 0xED, 0xFA, 0xCE])
MACHO_CIGAM32 = bytes([0xCE, 0xFA, 0xED, 0xFE])
MACHO_MAGIC64 = bytes([0xFE, 0xED, 0xFA, 0xCF])
MACHO_CIGAM64 = bytes([0xCF, 0xFA, 0xED, 0xFE])


class MachOHeader(object):
    def __init__(self, stream: io.RawIOBase):
        self.magic = stream.read(MACHO_UINT32)
        self.cputype = 0
        self.cpusubtype = 0
        self.filetype = 0
        self.ncmds = 0
        self.sizeofcmds = 0
        self.flags = 0
        self.reserved = 0

        if self.magic == MACHO_MAGIC32 or self.magic == MACHO_CIGAM32:
            self.__parse32(stream, self.endianness)
        elif self.magic == MACHO_MAGIC64 or self.magic == MACHO_CIGAM64:
            self.__parse64(stream, self.endianness)
        else:
            raise TypeError("Not a valid MachO")

        self.magic = int.from_bytes(self.magic, self.endianness)

    def __str__(self):
        return '\n'.join(['Mach-O HEADER',
                          'Magic:                       {magic:#x}',
                          'CPU type:                    {cputype}',
                          'CPU subtype:                 {cpusubtype}',
                          'Filetype:                    {filetype}',
                          'Number of commands:          {ncmds}',
                          'Size of commands:            {sizeofcmds}',
                          'Flags:                       {flags}']).format(**self.__dict__)

    def __parse32(self, stream: io.RawIOBase, endianness):
        self.cputype = int.from_bytes(stream.read(MACHO_CPUTYPE), byteorder=endianness)
        self.cpusubtype = int.from_bytes(stream.read(MACHO_CPUSTYPE), byteorder=endianness)
        self.filetype = int.from_bytes(stream.read(MACHO_UINT32), byteorder=endianness)
        self.ncmds = int.from_bytes(stream.read(MACHO_UINT32), byteorder=endianness)
        self.sizeofcmds = int.from_bytes(stream.read(MACHO_UINT32), byteorder=endianness)
        self.flags = int.from_bytes(stream.read(MACHO_UINT32), byteorder=endianness)

    def __parse64(self, stream: io.RawIOBase, endianness):
        self.cputype = int.from_bytes(stream.read(MACHO_CPUTYPE), byteorder=endianness)
        self.cpusubtype = int.from_bytes(stream.read(MACHO_CPUSTYPE), byteorder=endianness)
        self.filetype = int.from_bytes(stream.read(MACHO_UINT32), byteorder=endianness)
        self.ncmds = int.from_bytes(stream.read(MACHO_UINT32), byteorder=endianness)
        self.sizeofcmds = int.from_bytes(stream.read(MACHO_UINT32), byteorder=endianness)
        self.flags = int.from_bytes(stream.read(MACHO_UINT32), byteorder=endianness)
        self.reserved = int.from_bytes(stream.read(MACHO_UINT32), byteorder=endianness)

    def __should_swap_bytes(self):
        return self.magic == MACHO_CIGAM32 or self.magic == MACHO_CIGAM64

    @property
    def endianness(self):
        return 'little' if self.__should_swap_bytes() else 'big'


class MachO(object):
    def __init__(self, stream: io.RawIOBase):
        self.header = MachOHeader(stream)

    def __str__(self):
        return str(self.header)

    @staticmethod
    def verify(file: io.RawIOBase):
        s_pos = file.tell()
        magic = file.read(MACHO_UINT32)
        file.seek(s_pos)
        return magic == MACHO_MAGIC32 or magic == MACHO_CIGAM32 or magic == MACHO_MAGIC64 or magic == MACHO_CIGAM64
