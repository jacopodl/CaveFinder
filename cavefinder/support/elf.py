from cavefinder.support.cstruct import *

# MAGIC
ELF_MAGIC = bytes([0x7f, 0x45, 0x4c, 0x46])

# *****************************************
# * HEADER                                *
# *****************************************
EI_NIDENT = 16
EI_MAG0 = 0x00
EI_MAG1 = 0x01
EI_MAG2 = 0x02
EI_MAG3 = 0x03
EI_CLASS = 0x04
# *****************
EI_CLASSNONE = 0x00
EI_CLASS32 = 0x01
EI_CLASS64 = 0x02
# *****************
EI_DATA = 0x05
# *****************
EI_DATANONE = 0x00
EI_DATA2LSB = 0x01
EI_DATA2MSB = 0x02
# *****************
EI_VERSION = 0x06
EI_OSABI = 0x07
EI_ABIVERSION = 0x08
EI_PAD = 0x09

# *****************************************
# * SHDR                                  *
# *****************************************
SHT_TYPE_NULL = 0x00
SHT_TYPE_PROGBITS = 0x01
SHT_TYPE_SYMTAB = 0x02
SHT_TYPE_STRTAB = 0x03
SHT_TYPE_RELA = 0x04
SHT_TYPE_HASH = 0x05
SHT_TYPE_DYNAMIC = 0x06
SHT_TYPE_NOTE = 0x07
SHT_TYPE_NOBITS = 0x08
SHT_TYPE_REL = 0x09
SHT_TYPE_SHLIB = 0x0A
SHT_TYPE_DYNSYM = 0x0B
SHT_TYPE_LOPROC = 0x70000000
SHT_TYPE_HIPROC = 0x7FFFFFFF
SHT_TYPE_LOUSER = 0x80000000
SHT_TYPE_HIUSER = 0xFFFFFFFF
# Flags
SHT_FLAGS_WRITE = 0x01
SHT_FLAGS_ALLOC = 0x02
SHT_FLAGS_EXECINSTR = 0x04
SHT_FLAGS_MASKPROC = 0xF0000000


class ElfHeader(object):
    e_ident = []
    e_type = 0
    e_machine = 0
    e_version = 0
    e_entry = 0
    e_phoff = 0
    e_shoff = 0
    e_flags = 0
    e_ehsize = 0
    e_phentsize = 0
    e_phnum = 0
    e_shentsize = 0
    e_shnum = 0
    e_shstrnd = 0

    def __str__(self):
        return '\n'.join(['ELF Header',
                          'Magic:                       %s',
                          'ABI:                         %s',
                          'Type:                        {e_type:#} (%s)',
                          'Machine:                     {e_machine:#} (%s)',
                          'Endianness and word size:    %s endian - %d bit',
                          'Version:                     {e_version}',
                          'Entry point:                 {e_entry:#x}',
                          'Program header offset:       {e_phoff} - {e_phoff:#x} (bytes in file)',
                          'Section header offset:       {e_shoff} - {e_shoff:#x} (bytes in file)',
                          'Flags:                       {e_flags:#}',
                          'Size of this header:         {e_ehsize}',
                          'Size of program headers:     {e_phentsize}',
                          'Number of program headers:   {e_phnum}',
                          'Size of section headers:     {e_shentsize}',
                          'Number of section headers:   {e_shnum}',
                          'String table index:          {e_shstrnd:#}']) \
                   .format(**self.__dict__) % (" ".join([("%02x" % x).upper() for x in self.e_ident]),
                                               self.abi,
                                               self.type_str(),
                                               self.em_str(),
                                               self.endianness,
                                               32 if self.e_ident[EI_CLASS] == EI_CLASS32 else 64)

    @property
    def abi(self):
        abi = self.e_ident[EI_OSABI]
        val = {0x00: "System V",
               0x01: "HP-UX operating system",
               0xFF: "Standalone (embedded) application"}
        return "Unknown: %02x" % abi if abi not in val else val[abi]

    @property
    def endianness(self):
        return "big" if self.e_ident[EI_DATA] == EI_DATA2MSB else "little"

    def type_str(self):
        val = {0x00: "No file type",
               0x01: "Relocatable file",
               0x02: "Executable file",
               0x03: "Shared object",
               0x04: "Core file",
               0xFF00: "Processor-specific",
               0xFFFF: "Processor-specific"}

        return "Unknown: %02x" % self.e_type if self.e_type not in val else val[self.e_type]

    def em_str(self):
        val = {0x00: "No machine",
               0x01: "AT&T WE 32100",
               0x02: "SPARC",
               0x03: "Intel 80386",
               0x04: "Motorola 68000",
               0x05: "Motorola 88000",
               0x07: "Intel 80860",
               0x08: "MIPS RS3000",
               0x14: "PowerPC",
               0x28: "ARM",
               0x2A: "Superh",
               0x3E: "AMD x86-64",
               0xB7: "AArch64"}

        return "Unknown: %02x" % self.e_machine if self.e_machine not in val else val[self.e_machine]


class ElfHeader32(ElfHeader, metaclass=CStruct):
    e_ident = "16s"
    e_type = USHORT
    e_machine = USHORT
    e_version = UINT
    e_entry = UINT
    e_phoff = UINT
    e_shoff = UINT
    e_flags = UINT
    e_ehsize = USHORT
    e_phentsize = USHORT
    e_phnum = USHORT
    e_shentsize = USHORT
    e_shnum = USHORT
    e_shstrnd = USHORT

    def __init__(self, stream: io.RawIOBase, endianness):
        self.unpack_from_io(stream, endianness)


class ElfHeader64(ElfHeader, metaclass=CStruct):
    e_ident = "16s"
    e_type = USHORT
    e_machine = USHORT
    e_version = UINT
    e_entry = ULONGLONG
    e_phoff = ULONGLONG
    e_shoff = ULONGLONG
    e_flags = UINT
    e_ehsize = USHORT
    e_phentsize = USHORT
    e_phnum = USHORT
    e_shentsize = USHORT
    e_shnum = USHORT
    e_shstrnd = USHORT

    def __init__(self, stream: io.RawIOBase, endianness):
        self.unpack_from_io(stream, endianness)


class ElfShdr(object):
    sh_name = 0
    sh_type = 0
    sh_flags = 0
    sh_addr = 0
    sh_offset = 0
    sh_size = 0
    sh_link = 0
    sh_info = 0
    sh_addralign = 0
    sh_entsize = 0

    def type_str(self):
        val = {SHT_TYPE_NULL: "SHT_NULL",
               SHT_TYPE_PROGBITS: "SHT_PROGBITS",
               SHT_TYPE_SYMTAB: "SHT_SYMTAB",
               SHT_TYPE_STRTAB: "SHT_STRTAB",
               SHT_TYPE_RELA: "SHT_RELA",
               SHT_TYPE_HASH: "SHT_HASH",
               SHT_TYPE_DYNAMIC: "SHT_DYNAMIC",
               SHT_TYPE_NOTE: "SHT_NOTE",
               SHT_TYPE_NOBITS: "SHT_NOBITS",
               SHT_TYPE_REL: "SHT_REL",
               SHT_TYPE_SHLIB: "SHT_SHLIB",
               SHT_TYPE_DYNSYM: "SHT_DYNSYM",
               SHT_TYPE_LOPROC: "SHT_LOPROC",
               SHT_TYPE_HIPROC: "SHT_HIPROC",
               SHT_TYPE_LOUSER: "SHT_LOUSER",
               SHT_TYPE_HIUSER: "SHT_HIUSER"}
        return "Unknown: %02x" % self.sh_type if self.sh_type not in val else val[self.sh_type]

    def flags_str(self):
        retval = []
        val = {SHT_FLAGS_WRITE: "SHF_WRITE",
               SHT_FLAGS_ALLOC: "SHF_ALLOC",
               SHT_FLAGS_EXECINSTR: "SHF_EXECINSTR",
               SHT_FLAGS_MASKPROC: "SHF_MASKPROC"}
        for key in val:
            if self.sh_flags & key == key:
                retval.append(val[key])
        return " | ".join(retval)


class ElfShdr32(ElfShdr, metaclass=CStruct):
    sh_name = UINT
    sh_type = UINT
    sh_flags = UINT
    sh_addr = UINT
    sh_offset = UINT
    sh_size = UINT
    sh_link = UINT
    sh_info = UINT
    sh_addralign = UINT
    sh_entsize = UINT

    def __init__(self, stream: io.RawIOBase, endianness):
        self.unpack_from_io(stream, endianness)


class ElfShdr64(ElfShdr, metaclass=CStruct):
    sh_name = UINT
    sh_type = UINT
    sh_flags = ULONGLONG
    sh_addr = ULONGLONG
    sh_offset = ULONGLONG
    sh_size = ULONGLONG
    sh_link = UINT
    sh_info = UINT
    sh_addralign = ULONGLONG
    sh_entsize = ULONGLONG

    def __init__(self, stream: io.RawIOBase, endianness):
        self.unpack_from_io(stream, endianness)


class Elf:
    def __init__(self, stream: io.RawIOBase):
        self.sections = []
        self.shstr = None
        # Verify ELF and select wordsz and endianness
        minfo = stream.read(EI_NIDENT)
        stream.seek(stream.tell() - EI_NIDENT)
        if ELF_MAGIC not in minfo[0:4]:
            raise TypeError("Not a valid ELF")

        if minfo[EI_CLASS] == EI_CLASS32:
            self.header = ElfHeader32(stream, Elf.__parse_endianness(minfo[EI_DATA]))
            self.__section_loader(stream, ElfShdr32)
        elif minfo[EI_CLASS] == EI_CLASS64:
            self.header = ElfHeader64(stream, Elf.__parse_endianness(minfo[EI_DATA]))
            self.__section_loader(stream, ElfShdr64)
        else:
            raise RuntimeError("Invalid ELF class")

        # Load strings table
        stream.seek(self.sections[self.header.e_shstrnd].sh_offset)
        self.shstr = stream.read(self.sections[self.header.e_shstrnd].sh_size)

    def __str__(self):
        return str(self.header)

    def __section_loader(self, stream: io.RawIOBase, shdr):
        seek = self.header.e_shoff
        for _ in range(self.header.e_shnum):
            stream.seek(seek)
            self.sections.append(shdr(stream, self.header.endianness))
            seek += self.header.e_shentsize

    def get_section_name(self, section: ElfShdr):
        buf = bytearray()
        cursor = section.sh_name
        byte = self.shstr[cursor]
        while byte != 0x00:
            buf.append(byte)
            cursor += 1
            byte = self.shstr[cursor]
        return buf.decode("ascii")

    @staticmethod
    def __parse_endianness(value):
        return "big" if value == EI_DATA2MSB else "little"

    @staticmethod
    def verify(file: io.RawIOBase):
        s_pos = file.tell()
        ident = file.read(EI_NIDENT)
        ret = ELF_MAGIC in ident[0:4]
        file.seek(s_pos)
        return ret
