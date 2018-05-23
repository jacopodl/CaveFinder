from cavefinder.support.cstruct import *

# *****************
# *  Fat Header   *
# *****************
# | Mach-O Header |
# *****************
# | Load Commands |
# *****************
# |     Data      |
# *****************

# DataType
MACHO_UINT32 = 4
MACHO_UINT64 = 8
MACHO_CPUTYPE = 4
MACHO_CPUSTYPE = 4
MACHO_VM_PROT = 4

# MAGICS
MACHO_MAGIC32 = 0xFEEDFACE
MACHO_CIGAM32 = 0xCEFAEDFE
MACHO_MAGIC64 = 0xFEEDFACF
MACHO_CIGAM64 = 0xCFFAEDFE

MACHO_NAMESIZE = 16

# *****************************************
# * HEADER                                *
# *****************************************
MH_FLAGS_NOUNDEFS = 0x1
MH_FLAGS_INCRLINK = 0x2
MH_FLAGS_DYLDLINK = 0x4
MH_FLAGS_BINDATLOAD = 0x8
MH_FLAGS_PREBOUND = 0x10
MH_FLAGS_SPLIT_SEGS = 0x20
MH_FLAGS_LAZY_INIT = 0x40
MH_FLAGS_TWOLEVEL = 0x80
MH_FLAGS_FORCE_FLAT = 0x100
MH_FLAGS_NOMULTIDEFS = 0x200
MH_FLAGS_NOFIXPREBINDING = 0x400
MH_FLAGS_PREBINDABLE = 0x800
MH_FLAGS_ALLMODSBOUND = 0x1000
MH_FLAGS_SUBSECTIONS_VIA_SYMBOLS = 0x2000
MH_FLAGS_CANONICAL = 0x4000
MH_FLAGS_WEAK_DEFINES = 0x8000
MH_FLAGS_BINDS_TO_WEAK = 0x10000
MH_FLAGS_ALLOW_STACK_EXECUTION = 0x20000
MH_FLAGS_ROOT_SAFE = 0x40000
MH_FLAGS_SETUID_SAFE = 0x80000
MH_FLAGS_NO_REEXPORTED_DYLIBS = 0x100000
MH_FLAGS_PIE = 0x200000
MH_FLAGS_DEAD_STRIPPABLE_DYLIB = 0x400000
MH_FLAGS_HAS_TLV_DESCRIPTORS = 0x800000
MH_FLAGS_NO_HEAP_EXECUTION = 0x1000000


class MachOHeader(object):
    ABI64 = 0x01000000
    magic = 0
    cputype = 0
    cpusubtype = 0
    filetype = 0
    ncmds = 0
    sizeofcmds = 0
    flags = 0
    reserved = 0

    def __str__(self):
        return '\n'.join(['Mach-O Header',
                          'Magic:                       0x%02x',
                          'CPU type:                    %s',
                          'CPU subtype:                 {cpusubtype:#x}',
                          'Filetype:                    %s',
                          'Number of commands:          {ncmds}',
                          'Size of commands:            {sizeofcmds} bytes',
                          'Flags:                       {flags:#x} %s']) \
                   .format(**self.__dict__) % (self.magic, self.cputype_str(), self.filetype_str(), self.flags_str())

    @property
    def endianness(self):
        return "little" if (self.magic == MACHO_MAGIC32 or self.magic == MACHO_MAGIC64) else "big"

    @property
    def wordsz(self):
        if self.magic == MACHO_MAGIC32 or self.magic == MACHO_CIGAM32:
            return 32
        elif self.magic == MACHO_MAGIC64 or self.magic == MACHO_CIGAM64:
            return 64

    def cputype_str(self):
        val = {1: "VAX",
               6: "MC680x0",
               7: "Intel x86",
               7 | MachOHeader.ABI64: "AMD x86_64",
               10: "MC98000",
               11: "HPPA",
               12: "ARM",
               13: "MC88000",
               14: "SPARC",
               15: "I860",
               18: "PowerPC",
               18 | MachOHeader.ABI64: "PowerPC64"}

        return "Unknown: %02x" % self.cputype if self.cputype not in val else val[self.cputype]

    def filetype_str(self):
        val = {0x01: "Object",
               0x02: "Execute",
               0x03: "FVMLIB",
               0x04: "CORE",
               0x05: "PRELOAD",
               0x06: "DYLIB",
               0x07: "DYLINKER",
               0x08: "Bundle",
               0x09: "DYLIB_STUB",
               0x0A: "DSYM",
               0x0B: "Kext_Bundle"}

        return "Unknown: %02x" % self.cputype if self.cputype not in val else val[self.cputype]

    def flags_str(self):
        retval = []
        val = {MH_FLAGS_NOUNDEFS: "NOUNDEFS",
               MH_FLAGS_INCRLINK: "INCRLINK",
               MH_FLAGS_DYLDLINK: "DYLDLINK",
               MH_FLAGS_BINDATLOAD: "BINDATLOAD",
               MH_FLAGS_PREBOUND: "PREBOUND",
               MH_FLAGS_SPLIT_SEGS: "SPLIT_SEGS",
               MH_FLAGS_LAZY_INIT: "LAZY_INIT",
               MH_FLAGS_TWOLEVEL: "TWOLEVEL",
               MH_FLAGS_FORCE_FLAT: "FORCE_FLAT",
               MH_FLAGS_NOMULTIDEFS: "NOMULTIDEFS",
               MH_FLAGS_NOFIXPREBINDING: "NOFIXPREBINDING",
               MH_FLAGS_PREBINDABLE: "PREBINDABLE",
               MH_FLAGS_ALLMODSBOUND: "ALLMODSBOUND",
               MH_FLAGS_SUBSECTIONS_VIA_SYMBOLS: "SUBSECTIONS_VIA_SYMBOLS",
               MH_FLAGS_CANONICAL: "CANONICAL",
               MH_FLAGS_WEAK_DEFINES: "WEAK_DEFINES",
               MH_FLAGS_BINDS_TO_WEAK: "BINDS_TO_WEAK",
               MH_FLAGS_ALLOW_STACK_EXECUTION: "ALLOW_STACK_EXECUTION",
               MH_FLAGS_ROOT_SAFE: "ROOT_SAFE",
               MH_FLAGS_SETUID_SAFE: "SETUID_SAFE",
               MH_FLAGS_NO_REEXPORTED_DYLIBS: "NO_REEXPORTED_DYLIBS",
               MH_FLAGS_PIE: "PIE",
               MH_FLAGS_DEAD_STRIPPABLE_DYLIB: "DEAD_STRIPPABLE_DYLIB",
               MH_FLAGS_HAS_TLV_DESCRIPTORS: "HAS_TLV_DESCRIPTORS",
               MH_FLAGS_NO_HEAP_EXECUTION: "NO_HEAP_EXECUTION"}

        for key in val:
            if self.flags & key == key:
                retval.append(val[key])
        return " | ".join(retval)


class MachOHeader32(MachOHeader, metaclass=CStruct):
    magic = UINT
    cputype = UINT
    cpusubtype = UINT
    filetype = UINT
    ncmds = UINT
    sizeofcmds = UINT
    flags = UINT

    def __init__(self, stream: io.RawIOBase, endianness):
        self.unpack_from_io(stream, endianness)


class MachOHeader64(MachOHeader, metaclass=CStruct):
    magic = UINT
    cputype = UINT
    cpusubtype = UINT
    filetype = UINT
    ncmds = UINT
    sizeofcmds = UINT
    flags = UINT
    reserved = UINT

    def __init__(self, stream: io.RawIOBase, endianness):
        self.unpack_from_io(stream, endianness)


LC_SEGMENT = 0x1  # segment of this file to be mapped
LC_SYMTAB = 0x2  # link-edit stab symbol table info
LC_SYMSEG = 0x3  # link-edit gdb symbol table info (obsolete)
LC_THREAD = 0x4  # thread
LC_UNIXTHREAD = 0x5  # unix thread (includes a stack)
LC_LOADFVMLIB = 0x6  # load a specified fixed VM shared library
LC_IDFVMLIB = 0x7  # fixed VM shared library identification
LC_IDENT = 0x8  # object identification info (obsolete)
LC_FVMFILE = 0x9  # fixed VM file inclusion (internal use)
LC_PREPAGE = 0xA  # prepage command (internal use)
LC_DYSYMTAB = 0xB  # dynamic link-edit symbol table info
LC_LOAD_DYLIB = 0xC  # load a dynamically linked shared library
LC_ID_DYLIB = 0xD  # dynamically linked shared lib ident
LC_LOAD_DYLINKER = 0xE  # load a dynamic linker
LC_ID_DYLINKER = 0xF  # dynamic linker identification
LC_PREBOUND_DYLIB = 0x10  # modules prebound for a dynamically
LC_ROUTINES = 0x11  # image routines
LC_SUB_FRAMEWORK = 0x12  # sub framework
LC_SUB_UMBRELLA = 0x13  # sub umbrella
LC_SUB_CLIENT = 0x14  # sub client
LC_SUB_LIBRARY = 0x15  # sub library
LC_TWOLEVEL_HINTS = 0x16  # two-level namespace lookup hints
LC_PREBIND_CKSUM = 0x17  # prebind checksum
LC_SEGMENT_64 = 0x19

VMPROT_READ = 0x01
VMPROT_WRITE = 0x02
VMPROT_EXECUTE = 0x04


class MachOCommand(object, metaclass=CStruct):
    cmd = UINT
    cmdsize = UINT

    def __init__(self, stream: io.RawIOBase, header: MachOHeader, command=None):
        if command is None:
            self.unpack_from_io(stream, header.endianness)
        else:
            self.cmd = command.cmd
            self.cmdsize = command.cmdsize

    def __str__(self):
        return "\n".join(["Mach-O Command",
                          "Command:         {cmd}",
                          "Command size:    {cmdsize}"]).format(**self.__dict__)


class MachOSegment(MachOCommand):
    segname = str()
    vmaddr = 0
    vmsize = 0
    fileoff = 0
    filesize = 0
    maxprot = 0
    initprot = 0
    nsects = 0
    flags = 0

    def __init__(self, stream: io.RawIOBase, header: MachOHeader, command: MachOCommand):
        super().__init__(stream, header, command)
        self.sections = []
        self.unpack_from_io(stream, header.endianness)

        if self.cmd != LC_SEGMENT and self.cmd != LC_SEGMENT_64:
            raise TypeError("it is not a MachOSegment")

        # Load sections
        for section in range(self.nsects):
            if header.wordsz == 32:
                self.sections.append(MachOSection32(stream, header))
            elif header.wordsz == 64:
                self.sections.append(MachOSection64(stream, header))

    @property
    def initprot_str(self):
        return MachOSegment.__vmprot_str(self.initprot)

    @property
    def maxprot_str(self):
        return MachOSegment.__vmprot_str(self.maxprot)

    @staticmethod
    def __vmprot_str(vprot):
        retval = []
        val = {VMPROT_READ: "READ",
               VMPROT_WRITE: "WRITE",
               VMPROT_EXECUTE: "EXECUTE"}
        for key in val:
            if vprot & key == key:
                retval.append(val[key])
        return " | ".join(retval)


class MachOSegment32(MachOSegment):
    segname = "16s"
    vmaddr = UINT
    vmsize = UINT
    fileoff = UINT
    filesize = UINT
    maxprot = UINT
    initprot = UINT
    nsects = UINT
    flags = UINT


class MachOSegment64(MachOSegment):
    segname = "16s"
    vmaddr = ULONGLONG
    vmsize = ULONGLONG
    fileoff = ULONGLONG
    filesize = ULONGLONG
    maxprot = UINT
    initprot = UINT
    nsects = UINT
    flags = UINT


class MachOSection(object, metaclass=CStruct):
    sectname = str()
    segname = str()
    addr = 0
    size = 0
    offset = 0
    align = 0
    reloff = 0
    nreloc = 0
    flags = 0
    reserved1 = 0
    reserved2 = 0
    reserved3 = 0

    def __init__(self, stream: io.RawIOBase, header: MachOHeader):
        self.unpack_from_io(stream, header.endianness)
        self.sectname = self.sectname.decode("ascii")
        self.segname = self.segname.decode("ascii")


class MachOSection32(MachOSection):
    sectname = "16s"
    segname = "16s"
    addr = UINT
    size = UINT
    offset = UINT
    align = UINT
    reloff = UINT
    nreloc = UINT
    flags = UINT
    reserved1 = UINT
    reserved2 = UINT


class MachOSection64(MachOSection):
    sectname = "16s"
    segname = "16s"
    addr = ULONGLONG
    size = ULONGLONG
    offset = UINT
    align = UINT
    reloff = UINT
    nreloc = UINT
    flags = UINT
    reserved1 = UINT
    reserved2 = UINT
    reserved3 = UINT


class MachO(object):
    def __init__(self, stream: io.RawIOBase):
        self.segments = []

        # Verify MachO and select wordsz and endianness
        info = unpack_type(UINT, stream.read(sizeof(UINT)))
        stream.seek(stream.tell() - sizeof(UINT))
        if info == MACHO_MAGIC32 or info == MACHO_CIGAM32:
            self.header = MachOHeader32(stream, MachO.__parse_endianness(info))
        elif info == MACHO_MAGIC64 or info == MACHO_CIGAM64:
            self.header = MachOHeader64(stream, MachO.__parse_endianness(info))
        else:
            raise TypeError("Not a valid MachO")

        self.__load_commands(stream)

    def __str__(self):
        return str(self.header)

    def __load_commands(self, stream):
        seek = stream.tell()
        for _ in range(self.header.ncmds):
            command = MachOCommand(stream, self.header)
            if command.cmd == LC_SEGMENT or command.cmd == LC_SEGMENT_64:
                if self.header.wordsz == 32:
                    segment = MachOSegment32(stream, self.header, command)
                else:
                    segment = MachOSegment64(stream, self.header, command)
                self.segments.append(segment)
            seek += command.cmdsize
            stream.seek(seek)

    @staticmethod
    def __parse_endianness(value):
        return "little" if (value == MACHO_MAGIC32 or value == MACHO_MAGIC64) else "big"

    @staticmethod
    def verify(file: io.RawIOBase):
        s_pos = file.tell()
        magic = unpack_type(UINT, file.read(sizeof(UINT)))
        file.seek(s_pos)
        return magic == MACHO_MAGIC32 or magic == MACHO_CIGAM32 or magic == MACHO_MAGIC64 or magic == MACHO_CIGAM64
