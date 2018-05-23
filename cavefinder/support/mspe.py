from cavefinder.support.cstruct import *

# ---------------------
# | Dos Header        |
# ---------------------
# | Pe Signature      |
# ---------------------
# | COFF Header       |
# *********************
# | Optional Header   |
# *********************
# | Section Table     |
# ---------------------
# | Mappable sections |
# ---------------------

# 
MZ_MAGIC = 0x4D5A
MZ_CIGAM = 0x5A4D

PE_MAGIC = 0x50450000
PE_CIGAM = 0x00004550


class DosHeader(object, metaclass=CStruct):
    e_magic = USHORT  # 00: MZ Header signature
    e_cblp = USHORT  # 02: Bytes on last page of file
    e_cp = USHORT  # 04: Pages in file
    e_crlc = USHORT  # 06: Relocations
    e_cparhdr = USHORT  # 08: Size of header in paragraphs
    e_minalloc = USHORT  # 0a: Minimum extra paragraphs needed
    e_maxalloc = USHORT  # 0c: Maximum extra paragraphs needed
    e_ss = USHORT  # 0e: Initial (relative) SS value
    e_sp = USHORT  # 10: Initial SP value
    e_csum = USHORT  # 12: Checksum
    e_ip = USHORT  # 14: Initial IP value
    e_cs = USHORT  # 16: Initial (relative) CS value
    e_lfarlc = USHORT  # 18: File address of relocation table
    e_ovno = USHORT  # 1a: Overlay number
    e_res = "8s"  # 1c: Reserved words
    e_oemid = USHORT  # 24: OEM identifier (for e_oeminfo)
    e_oeminfo = USHORT  # 26: OEM information=0 e_oemid specific
    e_res2 = "20s"  # 28: Reserved words
    e_lfanew = UINT  # 3c: Offset to extended header

    def __init__(self, stream: io.RawIOBase):
        self.e_magic = unpack_type(USHORT, stream.read(2))
        stream.seek(stream.tell() - sizeof(USHORT))

        if self.e_magic == MZ_CIGAM or MZ_MAGIC:
            self.unpack_from_io(stream)
        else:
            raise TypeError("Not a valid PE (Invalid DosHeader)")

    def __str__(self):
        return '\n'.join(["Dos Header:",
                          "Magic:                       {e_magic:#x}",
                          "Byte on last page:           {e_cblp:#x}",
                          "Page in file:                {e_cp:#x}",
                          "Relocations:                 {e_crlc:#x}",
                          "Size of header:              {e_cparhdr:#x}",
                          "Min alloc:                   {e_minalloc:#x}",
                          "Max alloc:                   {e_maxalloc:#x}",
                          "ss:                          {e_ss:#x}",
                          "sp:                          {e_sp:#x}",
                          "Checksum:                    {e_csum:#x}",
                          "ip:                          {e_ip:#x}",
                          "cs:                          {e_cs:#x}",
                          "File address reloc table:    {e_lfarlc:#x}",
                          "Overlay number:              {e_ovno:#x}",
                          "OEM id:                      {e_oemid:#x}",
                          "OEM info:                    {e_oeminfo:#x}",
                          "Offset to extended header:   {e_lfanew:#x}"]).format(**self.__dict__)

    @property
    def endianness(self):
        return 'big' if self.e_magic == MZ_MAGIC else 'little'


COFF_MACHINE_UNKNOWN = 0  # unknown
COFF_MACHINE_I386 = 0x014c  # Intel 386.
COFF_MACHINE_R3000 = 0x0162  # MIPS little-endian, 0x160 big-endian
COFF_MACHINE_R4000 = 0x0166  # MIPS little-endian
COFF_MACHINE_R10000 = 0x0168  # MIPS little-endian
COFF_MACHINE_WCEMIPSV2 = 0x0169  # MIPS little-endian WCE v2
COFF_MACHINE_ALPHA = 0x0184  # Alpha_AXP
COFF_MACHINE_POWERPC = 0x01F0  # IBM PowerPC Little-Endian
COFF_MACHINE_SH3 = 0x01a2  # SH3 little-endian
COFF_MACHINE_SH3E = 0x01a4  # SH3E little-endian
COFF_MACHINE_SH4 = 0x01a6  # SH4 little-endian
COFF_MACHINE_ARM = 0x01c0  # ARM Little-Endian
COFF_MACHINE_THUMB = 0x01c2
COFF_MACHINE_AMD64 = 0x8664
COFF_MACHINE_IA64 = 0x0200  # Intel 64
COFF_MACHINE_MIPS16 = 0x0266  # MIPS
COFF_MACHINE_MIPSFPU = 0x0366  # MIPS
COFF_MACHINE_MIPSFPU16 = 0x0466  # MIPS
COFF_MACHINE_ALPHA64 = 0x0284  # ALPHA64


class COFFHeader(object, metaclass=CStruct):
    machine = USHORT
    nsections = USHORT
    timestamp = UINT
    ptr_to_symtable = UINT
    nsym = UINT
    size_opheader = USHORT
    characteristics = USHORT

    def __init__(self, stream: io.RawIOBase, endianness):
        self.unpack_from_io(stream, endianness)

    def __str__(self):
        return "\n".join(["Machine:                 {machine:#x} (%s)",
                          "Number of sections:      {nsections}",
                          "Timestamp:               {timestamp}",
                          "Ptr to symbol table:     {ptr_to_symtable:#x}",
                          "Number of symbol:        {nsym}",
                          "Size of optional header: {size_opheader}",
                          "Characteristics:         {characteristics:#x}"]).format(**self.__dict__) % self.machine_str

    @property
    def machine_str(self):
        val = {
            COFF_MACHINE_UNKNOWN: "unknown",
            COFF_MACHINE_I386: "Intel 386",
            COFF_MACHINE_R3000: "MIPS little-endian",
            COFF_MACHINE_R4000: "MIPS little-endian",
            COFF_MACHINE_R10000: "MIPS little-endian",
            COFF_MACHINE_WCEMIPSV2: "MIPS little-endian WCE v2",
            COFF_MACHINE_ALPHA: "Alpha_AXP",
            COFF_MACHINE_POWERPC: "PowerPC little-endian",
            COFF_MACHINE_SH3: "SH3 little-endian",
            COFF_MACHINE_SH3E: "SH3E little-endian",
            COFF_MACHINE_SH4: "SH4 little-endian",
            COFF_MACHINE_ARM: "ARM little-endian",
            COFF_MACHINE_THUMB: "THUMB",
            COFF_MACHINE_AMD64: "AMD 64",
            COFF_MACHINE_IA64: "Intel 64",
            COFF_MACHINE_MIPS16: "MIPS",
            COFF_MACHINE_MIPSFPU: "MIPS",
            COFF_MACHINE_MIPSFPU16: "MIPS",
            COFF_MACHINE_ALPHA64: "ALPHA64"
        }

        return "Unknown: %02x" % self.machine if self.machine not in val else val[self.machine]


IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107

IMAGE_SUBSYSTEM_UNKNOWN = 0x0
IMAGE_SUBSYSTEM_NATIVE = 0x1
IMAGE_SUBSYSTEM_WINDOWS_GUI = 0x2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 0x3
IMAGE_SUBSYSTEM_OS2_CUI = 0x5
IMAGE_SUBSYSTEM_POSIX_CUI = 0x7
IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 0x8
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 0x9


class OptionalHeader(object, metaclass=CStruct):
    magic = USHORT
    major_linker_version = UCHAR
    minor_linker_version = UCHAR
    size_of_code = UINT
    size_initialized_data = UINT
    size_uninitialized_data = UINT
    address_entry_point = UINT
    base_code = UINT
    image_base = ULONGLONG
    section_alignment = UINT
    file_alignment = UINT
    major_osversion = USHORT
    minor_osversion = USHORT
    major_image_version = USHORT
    minor_image_version = USHORT
    major_subsystem_version = USHORT
    minor_subsystem_version = USHORT
    win32_version = UINT
    size_image = UINT
    size_headers = UINT
    checksum = UINT
    subsystem = USHORT
    dll_characteristics = USHORT
    size_stack_reserve = ULONGLONG
    size_stack_commit = ULONGLONG
    size_heap_reserve = ULONGLONG
    size_heap_commit = ULONGLONG
    loader_flags = UINT
    number_rva_and_sizes = UINT

    def __init__(self, stream: io.RawIOBase, endianness):
        self.unpack_from_io(stream, endianness)

    def subsytem_str(self):
        val = {
            IMAGE_SUBSYSTEM_UNKNOWN: "Unknown",
            IMAGE_SUBSYSTEM_NATIVE: "Native",
            IMAGE_SUBSYSTEM_WINDOWS_GUI: "Windows GUI",
            IMAGE_SUBSYSTEM_WINDOWS_CUI: "Console",
            IMAGE_SUBSYSTEM_OS2_CUI: "OS/2 Console",
            IMAGE_SUBSYSTEM_POSIX_CUI: "Posix Console",
            IMAGE_SUBSYSTEM_NATIVE_WINDOWS: "diver 9x native",
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: "Windows CE",
        }
        return "Unknown: %02x" % self.subsystem if self.subsystem not in val else val[self.subsystem]

    @property
    def wordsz(self):
        if self.magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return 32
        elif self.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return 64
        return 0


class PeSectionHeader(object, metaclass=CStruct):
    name = "8s"
    physaddr_or_virtsize = UINT
    virtual_addr = UINT
    size_rawdata = UINT
    ptr_rawdata = UINT
    ptr_relocations = UINT
    ptr_linenumbers = UINT
    nrelocations = USHORT
    nlinenumbers = USHORT
    characteristics = UINT

    def __init__(self, stream: io.RawIOBase, endianness):
        self.unpack_from_io(stream, endianness)

    def __str__(self):
        return "\n".join(["Section Header",
                          "Name:                    {name}",
                          "Virtual address:         {virtual_addr:#x}",
                          "Size of raw data:        {size_rawdata:#x}",
                          "Pointer to raw data:     {ptr_rawdata:#x}",
                          "Pointer to relocations:  {ptr_relocations:#x}",
                          "Pointer to line numbers: {ptr_linenumbers:#x}",
                          "Number of relocations:   {nrelocations:#x}",
                          "Number of line numbers:  {nlinenumbers:#x}",
                          "Characteristics:         {characteristics:#x}"]).format(**self.__dict__)


class PEHeader(object):
    def __init__(self, stream: io.RawIOBase, offset=0):
        if offset > 0:
            stream.seek(offset)

        self.signature = unpack_type(UINT, stream.read(4))
        if self.signature != PE_MAGIC and self.signature != PE_CIGAM:
            raise TypeError("Not a valid PE (Invalid NT signature)")

        self.file_header = COFFHeader(stream, self.endianness)

        # Parse optional header
        self.optional_header = None
        jmp_op = stream.tell()
        if self.file_header.size_opheader > 0:
            self.optional_header = OptionalHeader(stream, self.endianness)
        stream.seek(jmp_op + self.file_header.size_opheader)

    def __str__(self):
        return str(self.file_header)

    @property
    def endianness(self):
        return "big" if self.signature == PE_MAGIC else "little"


class Pe(object):
    def __init__(self, stream: io.RawIOBase):
        self.dos_header = DosHeader(stream)
        self.pe_header = PEHeader(stream, self.dos_header.e_lfanew)

        # Parse sections
        self.sections = []
        for _ in range(self.pe_header.file_header.nsections):
            self.sections.append(PeSectionHeader(stream, self.pe_header.endianness))

    def __str__(self):
        return "\n".join(["Pe Header",
                          "Magic:                   0x%02x",
                          "%s"]) % (self.pe_header.signature, str(self.pe_header))

    @staticmethod
    def verify(file: io.RawIOBase):
        s_pos = file.tell()
        magic = unpack_type(USHORT, file.read(2))  # MS_WORD
        file.seek(s_pos)
        return magic == MZ_MAGIC or magic == MZ_CIGAM
