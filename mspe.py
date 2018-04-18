import io

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

MS_CHAR = 1
MS_WORD = 2
MS_DWORD = 4
MS_QWORD = 8

# 
MZ_CIGAM = bytes([0x4D, 0x5A])
MZ_MAGIC = bytes([0x5A, 0x4D])

PE_CIGAM = bytes([0x50, 0x45, 0x00, 0x00])
PE_MAGIC = bytes([0x00, 0x00, 0x45, 0x50])


class DosHeader(object):
    def __init__(self, stream: io.RawIOBase):
        self.e_magic = 0  # 00: MZ Header signature
        self.e_cblp = 0  # 02: Bytes on last page of file
        self.e_cp = 0  # 04: Pages in file
        self.e_crlc = 0  # 06: Relocations
        self.e_cparhdr = 0  # 08: Size of header in paragraphs
        self.e_minalloc = 0  # 0a: Minimum extra paragraphs needed
        self.e_maxalloc = 0  # 0c: Maximum extra paragraphs needed
        self.e_ss = 0  # 0e: Initial (relative) SS value
        self.e_sp = 0  # 10: Initial SP value
        self.e_csum = 0  # 12: Checksum
        self.e_ip = 0  # 14: Initial IP value
        self.e_cs = 0  # 16: Initial (relative) CS value
        self.e_lfarlc = 0  # 18: File address of relocation table
        self.e_ovno = 0  # 1a: Overlay number
        self.e_res = bytes(4)  # 1c: Reserved words
        self.e_oemid = 0  # 24: OEM identifier (for e_oeminfo)
        self.e_oeminfo = 0  # 26: OEM information=0 e_oemid specific
        self.e_res2 = bytes(10)  # 28: Reserved words
        self.e_lfanew = 0  # 3c: Offset to extended header

        self.e_magic = stream.read(2 * MS_CHAR)

        if self.e_magic == MZ_CIGAM or MZ_MAGIC:
            self.__parse(stream, self.endianness)
        else:
            raise TypeError("Not a valid PE (Invalid DosHeader)")

    def __str__(self):
        return '\n'.join(["Dos Header:",
                          "Magic:                       {e_magic}",
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

    def __parse(self, stream: io.RawIOBase, endianness):
        self.e_cblp = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_cp = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_crlc = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_cparhdr = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_minalloc = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_maxalloc = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_ss = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_sp = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_csum = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_ip = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_cs = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_lfarlc = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_ovno = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_res = stream.read(4 * MS_WORD)
        self.e_oemid = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_oeminfo = int.from_bytes(stream.read(MS_WORD), endianness)
        self.e_res2 = stream.read(10 * MS_WORD)
        self.e_lfanew = int.from_bytes(stream.read(MS_DWORD), endianness)

    @property
    def endianness(self):
        return 'little' if self.e_magic == MZ_CIGAM else 'big'


class COFFHeader(object):
    MACHINE_UNKNOWN = 0  # sconosciuta
    MACHINE_I386 = 0x014c  # Intel 386.
    MACHINE_R3000 = 0x0162  # MIPS little-endian, 0x160 big-endian
    MACHINE_R4000 = 0x0166  # MIPS little-endian
    MACHINE_R10000 = 0x0168  # MIPS little-endian
    MACHINE_WCEMIPSV2 = 0x0169  # MIPS little-endian WCE v2
    MACHINE_ALPHA = 0x0184  # Alpha_AXP
    MACHINE_POWERPC = 0x01F0  # IBM PowerPC Little-Endian
    MACHINE_SH3 = 0x01a2  # SH3 little-endian
    MACHINE_SH3E = 0x01a4  # SH3E little-endian
    MACHINE_SH4 = 0x01a6  # SH4 little-endian
    MACHINE_ARM = 0x01c0  # ARM Little-Endian
    MACHINE_THUMB = 0x01c2
    MACHINE_AMD64 = 0x8664
    MACHINE_IA64 = 0x0200  # Intel 64
    MACHINE_MIPS16 = 0x0266  # MIPS
    MACHINE_MIPSFPU = 0x0366  # MIPS
    MACHINE_MIPSFPU16 = 0x0466  # MIPS
    MACHINE_ALPHA64 = 0x0284  # ALPHA64

    def __init__(self, stream: io.RawIOBase, endianness):
        self.machine = int.from_bytes(stream.read(MS_WORD), endianness)
        self.nsections = int.from_bytes(stream.read(MS_WORD), endianness)
        self.timestamp = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.ptr_to_symtable = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.nsym = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.size_opheader = int.from_bytes(stream.read(MS_WORD), endianness)
        self.characteristics = int.from_bytes(stream.read(MS_WORD), endianness)

    def __str__(self):
        return "\n".join(["Machine:                 {machine} (%s)",
                          "Number of sections:      {nsections}",
                          "Timestamp:               {timestamp}",
                          "Ptr to symbol table:     {ptr_to_symtable}",
                          "Number of symbol:        {nsym}",
                          "Size of optional header: {size_opheader}",
                          "Characteristics:         {characteristics}"]).format(**self.__dict__) % self.machine_str

    @property
    def machine_str(self):
        val = {
            COFFHeader.MACHINE_UNKNOWN: "unknown",
            COFFHeader.MACHINE_I386: "Intel 386",
            COFFHeader.MACHINE_R3000: "MIPS little-endian",
            COFFHeader.MACHINE_R4000: "MIPS little-endian",
            COFFHeader.MACHINE_R10000: "MIPS little-endian",
            COFFHeader.MACHINE_WCEMIPSV2: "MIPS little-endian WCE v2",
            COFFHeader.MACHINE_ALPHA: "Alpha_AXP",
            COFFHeader.MACHINE_POWERPC: "PowerPC little-endian",
            COFFHeader.MACHINE_SH3: "SH3 little-endian",
            COFFHeader.MACHINE_SH3E: "SH3E little-endian",
            COFFHeader.MACHINE_SH4: "SH4 little-endian",
            COFFHeader.MACHINE_ARM: "ARM little-endian",
            COFFHeader.MACHINE_THUMB: "THUMB",
            COFFHeader.MACHINE_AMD64: "AMD 64",
            COFFHeader.MACHINE_IA64: "Intel 64",
            COFFHeader.MACHINE_MIPS16: "MIPS",
            COFFHeader.MACHINE_MIPSFPU: "MIPS",
            COFFHeader.MACHINE_MIPSFPU16: "MIPS",
            COFFHeader.MACHINE_ALPHA64: "ALPHA64"
        }

        return "Unknown: %02x" % self.machine if self.machine not in val else val[self.machine]


class OptionalHeader(object):
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

    def __init__(self, stream: io.RawIOBase, endianness):
        self.magic = int.from_bytes(stream.read(MS_WORD), endianness)
        self.major_linker_version = int.from_bytes(stream.read(MS_CHAR), endianness)
        self.minor_linker_version = int.from_bytes(stream.read(MS_CHAR), endianness)
        self.size_of_code = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.size_initialized_data = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.size_uninitialized_data = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.address_entry_point = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.base_code = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.image_base = int.from_bytes(stream.read(MS_QWORD), endianness)
        self.section_alignment = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.file_alignment = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.major_osversion = int.from_bytes(stream.read(MS_WORD), endianness)
        self.minor_osversion = int.from_bytes(stream.read(MS_WORD), endianness)
        self.major_image_version = int.from_bytes(stream.read(MS_WORD), endianness)
        self.minor_image_version = int.from_bytes(stream.read(MS_WORD), endianness)
        self.major_subsystem_version = int.from_bytes(stream.read(MS_WORD), endianness)
        self.minor_subsystem_version = int.from_bytes(stream.read(MS_WORD), endianness)
        self.win32_version = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.size_image = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.size_headers = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.checksum = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.subsystem = int.from_bytes(stream.read(MS_WORD), endianness)
        self.dll_characteristics = int.from_bytes(stream.read(MS_WORD), endianness)
        self.size_stack_reserve = int.from_bytes(stream.read(MS_QWORD), endianness)
        self.size_stack_commit = int.from_bytes(stream.read(MS_QWORD), endianness)
        self.size_heap_reserve = int.from_bytes(stream.read(MS_QWORD), endianness)
        self.size_heap_commit = int.from_bytes(stream.read(MS_QWORD), endianness)
        self.loader_flags = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.number_rva_and_sizes = int.from_bytes(stream.read(MS_DWORD), endianness)

    def subsytem_str(self):
        val = {
            OptionalHeader.IMAGE_SUBSYSTEM_UNKNOWN: "Unknown",
            OptionalHeader.IMAGE_SUBSYSTEM_NATIVE: "Native",
            OptionalHeader.IMAGE_SUBSYSTEM_WINDOWS_GUI: "Windows GUI",
            OptionalHeader.IMAGE_SUBSYSTEM_WINDOWS_CUI: "Console",
            OptionalHeader.IMAGE_SUBSYSTEM_OS2_CUI: "OS/2 Console",
            OptionalHeader.IMAGE_SUBSYSTEM_POSIX_CUI: "Posix Console",
            OptionalHeader.IMAGE_SUBSYSTEM_NATIVE_WINDOWS: "diver 9x native",
            OptionalHeader.IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: "Windows CE",
        }
        return "Unknown: %02x" % self.subsystem if self.subsystem not in val else val[self.subsystem]

    @property
    def wordsz(self):
        if self.magic == OptionalHeader.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return 32
        elif self.magic == OptionalHeader.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return 64
        return 0


class PeSectionHeader(object):
    SECTION_NAME_LEN = 8

    def __init__(self, stream: io.RawIOBase, endianness):
        self.name = stream.read(PeSectionHeader.SECTION_NAME_LEN).decode("ascii")
        self.physaddr_or_virtsize = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.virtual_addr = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.size_rawdata = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.ptr_rawdata = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.ptr_relocations = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.ptr_linenumbers = int.from_bytes(stream.read(MS_DWORD), endianness)
        self.nrelocations = int.from_bytes(stream.read(MS_WORD), endianness)
        self.nlinenumbers = int.from_bytes(stream.read(MS_WORD), endianness)
        self.characteristics = int.from_bytes(stream.read(MS_DWORD), endianness)

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
    def __init__(self, stream: io.RawIOBase):
        self.signature = stream.read(MS_DWORD)
        if PE_CIGAM not in self.signature and PE_MAGIC not in self.signature:
            raise TypeError("Not a valid PE (Invalid NT signature)")

        self.file_header = COFFHeader(stream, self.endianness)

        # Parse optional header
        self.optional_header = None
        jmp_op = stream.tell()
        if self.file_header.size_opheader > 0:
            self.optional_header = OptionalHeader(stream, self.endianness)
        stream.seek(jmp_op + self.file_header.size_opheader)

    @property
    def endianness(self):
        return 'little' if PE_CIGAM in self.signature else 'big'


class Pe(object):
    def __init__(self, stream: io.RawIOBase):
        self.dos_header = DosHeader(stream)
        stream.seek(self.dos_header.e_lfanew)
        self.pe_header = PEHeader(stream)

        # Parse sections
        self.sections = []
        for _ in range(self.pe_header.file_header.nsections):
            self.sections.append(PeSectionHeader(stream, self.pe_header.endianness))

    @staticmethod
    def verify(file: io.RawIOBase):
        s_pos = file.tell()
        magic = file.read(MS_WORD)
        file.seek(s_pos)
        return magic == MZ_MAGIC or magic == MZ_CIGAM
