import io

ELF32_ADDR = 4
ELF32_HALF = 2
ELF32_OFF = 4
ELF32_SWORD = 4
ELF32_WORD = 4
ELF32_LWORD = 8

ELF64_ADDR = 8
ELF64_HALF = 2
ELF64_OFF = 8
ELF64_SWORD = 4
ELF64_SXWORD = 8
ELF64_WORD = 4
ELF64_LWORD = 8
ELF64_XWORD = 8


class ElfHeader(object):
    NIDENT = 16
    MAG0 = 0x00
    MAG1 = 0x01
    MAG2 = 0x02
    MAG3 = 0x03
    CLASS = 0x04
    DATA = 0x05
    VERSION = 0x06
    OSABI = 0x07
    ABIVERSION = 0x08
    PAD = 0x09

    # Class
    CLASSNONE = 0x00
    CLASS32 = 0x01
    CLASS64 = 0x02

    # Encoding
    DATANONE = 0x00
    DATA2LSB = 0x01
    DATA2MSB = 0x02

    def __init__(self, stream: io.RawIOBase):
        self.stream = stream
        self.e_ident = bytes(ElfHeader.NIDENT)
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrnd = 0

        self.e_ident = self.stream.read(ElfHeader.NIDENT)
        if self.wordsz == 32:
            self.__parse32(stream, self.endianness)
        elif self.wordsz == 64:
            self.__parse64(stream, self.endianness)

    def __parse32(self, stream: io.RawIOBase, endianness):
        self.e_type = int.from_bytes(stream.read(ELF32_HALF), byteorder=endianness)
        self.e_machine = int.from_bytes(stream.read(ELF32_HALF), byteorder=endianness)
        self.e_version = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)
        self.e_entry = int.from_bytes(stream.read(ELF32_ADDR), byteorder=endianness)
        self.e_phoff = int.from_bytes(stream.read(ELF32_OFF), byteorder=endianness)
        self.e_shoff = int.from_bytes(stream.read(ELF32_OFF), byteorder=endianness)
        self.e_flags = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)
        self.e_ehsize = int.from_bytes(stream.read(ELF32_HALF), byteorder=endianness)
        self.e_phentsize = int.from_bytes(stream.read(ELF32_HALF), byteorder=endianness)
        self.e_phnum = int.from_bytes(stream.read(ELF32_HALF), byteorder=endianness)
        self.e_shentsize = int.from_bytes(stream.read(ELF32_HALF), byteorder=endianness)
        self.e_shnum = int.from_bytes(stream.read(ELF32_HALF), byteorder=endianness)
        self.e_shstrnd = int.from_bytes(stream.read(ELF32_HALF), byteorder=endianness)

    def __parse64(self, stream: io.RawIOBase, endianness):
        self.e_type = int.from_bytes(stream.read(ELF64_HALF), byteorder=endianness)
        self.e_machine = int.from_bytes(stream.read(ELF64_HALF), byteorder=endianness)
        self.e_version = int.from_bytes(stream.read(ELF64_WORD), byteorder=endianness)
        self.e_entry = int.from_bytes(stream.read(ELF64_ADDR), byteorder=endianness)
        self.e_phoff = int.from_bytes(stream.read(ELF64_OFF), byteorder=endianness)
        self.e_shoff = int.from_bytes(stream.read(ELF64_OFF), byteorder=endianness)
        self.e_flags = int.from_bytes(stream.read(ELF64_WORD), byteorder=endianness)
        self.e_ehsize = int.from_bytes(stream.read(ELF64_HALF), byteorder=endianness)
        self.e_phentsize = int.from_bytes(stream.read(ELF64_HALF), byteorder=endianness)
        self.e_phnum = int.from_bytes(stream.read(ELF64_HALF), byteorder=endianness)
        self.e_shentsize = int.from_bytes(stream.read(ELF64_HALF), byteorder=endianness)
        self.e_shnum = int.from_bytes(stream.read(ELF64_HALF), byteorder=endianness)
        self.e_shstrnd = int.from_bytes(stream.read(ELF64_HALF), byteorder=endianness)

    def __str__(self):
        return '\n'.join(['ELF HEADER',
                          'Magic:                       7F 45 4C 46',
                          'ABI:                         %s',
                          'Type:                        {e_type} %s',
                          'Machine:                     {e_machine} %s',
                          'Endianness and word size:    %s endian - %d bit',
                          'Version:                     {e_version}',
                          'Entry point:                 {e_entry:#x}',
                          'Program header offset:       {e_phoff} - {e_phoff:#x} (bytes in file)',
                          'Section header offset:       {e_shoff} - {e_shoff:#x} (bytes in file)',
                          'Flags:                       {e_flags}',
                          'Size of this header:         {e_ehsize}',
                          'Size of program headers:     {e_phentsize}',
                          'Number of program headers:   {e_phnum}',
                          'Size of section headers:     {e_shentsize}',
                          'Number of section headers:   {e_shnum}',
                          'String table index:          {e_shstrnd}']) \
                   .format(**self.__dict__) % (self.abi,
                                               ElfHeader.type_tostr(self.e_type),
                                               ElfHeader.em_tostr(self.e_machine),
                                               self.endianness,
                                               self.wordsz)

    @property
    def abi(self):
        abi = self.e_ident[ElfHeader.OSABI]
        val = {0x00: 'System V',
               0x01: 'HP-UX operating system',
               0xFF: 'Standalone (embedded) application'}
        return "Unknown: %02x" % abi if abi not in val else val[abi]

    @property
    def endianness(self):
        return 'little' if self.e_ident[ElfHeader.DATA] == ElfHeader.DATA2LSB else 'big'

    @property
    def wordsz(self):
        return 32 if self.e_ident[ElfHeader.CLASS] == ElfHeader.CLASS32 else 64

    @staticmethod
    def type_tostr(etype):
        val = {0x00: "No file type",
               0x01: "Relocatable file",
               0x02: "Executable file",
               0x03: "Shared object",
               0x04: "Core file",
               0xFF00: "Processor-specific",
               0xFFFF: "Processor-specific"}

        return "Unknown: %02x" % etype if etype not in val else val[etype]

    @staticmethod
    def em_tostr(elf_machine):
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

        return "Unknown: %02x" % elf_machine if elf_machine not in val else val[elf_machine]


class ElfShdr(object):
    def __init__(self, stream: io.RawIOBase, header: ElfHeader):
        self.sh_name = 0
        self.sh_type = 0
        self.sh_flags = 0
        self.sh_addr = 0
        self.sh_offset = 0
        self.sh_size = 0
        self.sh_link = 0
        self.sh_info = 0
        self.sh_addralign = 0
        self.sh_entsize = 0

        if header.wordsz == 32:
            self.__parse32(stream, header.endianness)
        elif header.wordsz == 64:
            self.__parse64(stream, header.endianness)

    def __parse32(self, stream: io.RawIOBase, endianness):
        self.sh_name = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)
        self.sh_type = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)
        self.sh_flags = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)
        self.sh_addr = int.from_bytes(stream.read(ELF32_ADDR), byteorder=endianness)
        self.sh_offset = int.from_bytes(stream.read(ELF32_OFF), byteorder=endianness)
        self.sh_size = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)
        self.sh_link = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)
        self.sh_info = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)
        self.sh_addralign = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)
        self.sh_entsize = int.from_bytes(stream.read(ELF32_WORD), byteorder=endianness)

    def __parse64(self, stream: io.RawIOBase, endianness):
        self.sh_name = int.from_bytes(stream.read(ELF64_WORD), byteorder=endianness)
        self.sh_type = int.from_bytes(stream.read(ELF64_WORD), byteorder=endianness)
        self.sh_flags = int.from_bytes(stream.read(ELF64_XWORD), byteorder=endianness)
        self.sh_addr = int.from_bytes(stream.read(ELF64_ADDR), byteorder=endianness)
        self.sh_offset = int.from_bytes(stream.read(ELF64_OFF), byteorder=endianness)
        self.sh_size = int.from_bytes(stream.read(ELF64_XWORD), byteorder=endianness)
        self.sh_link = int.from_bytes(stream.read(ELF64_WORD), byteorder=endianness)
        self.sh_info = int.from_bytes(stream.read(ELF64_WORD), byteorder=endianness)
        self.sh_addralign = int.from_bytes(stream.read(ELF64_XWORD), byteorder=endianness)
        self.sh_entsize = int.from_bytes(stream.read(ELF64_XWORD), byteorder=endianness)


class Elf:
    ELF_MAGIC = bytearray([0x7f, 0x45, 0x4c, 0x46])

    def __init__(self, stream: io.RawIOBase):
        if not Elf.verify(stream):
            raise TypeError("Not a valid ELF")

        self.header = ElfHeader(stream)
        self.sections = []
        self.shstr = bytes()

        # Sections
        seek = self.header.e_shoff
        for _ in range(self.header.e_shnum):
            stream.seek(seek)
            self.sections.append(ElfShdr(stream, self.header))
            seek += self.header.e_shentsize

        # Load strings table
        stream.seek(self.sections[self.header.e_shstrnd].sh_offset)
        self.shstr = stream.read(self.sections[self.header.e_shstrnd].sh_size)

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
    def verify(file: io.RawIOBase):
        s_pos = file.tell()
        ident = file.read(ElfHeader.NIDENT)
        ret = Elf.ELF_MAGIC in ident[0:4]
        file.seek(s_pos)
        return ret
