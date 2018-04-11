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
MACHO_UINT64 = 8
MACHO_CPUTYPE = 4
MACHO_CPUSTYPE = 4
MACHO_VM_PROT = 4

MACHO_MAGIC32 = bytes([0xFE, 0xED, 0xFA, 0xCE])
MACHO_CIGAM32 = bytes([0xCE, 0xFA, 0xED, 0xFE])
MACHO_MAGIC64 = bytes([0xFE, 0xED, 0xFA, 0xCF])
MACHO_CIGAM64 = bytes([0xCF, 0xFA, 0xED, 0xFE])


class MachOHeader(object):
    ABI64 = 0x01000000

    FLAGS_NOUNDEFS = 0x1
    FLAGS_INCRLINK = 0x2
    FLAGS_DYLDLINK = 0x4
    FLAGS_BINDATLOAD = 0x8
    FLAGS_PREBOUND = 0x10
    FLAGS_SPLIT_SEGS = 0x20
    FLAGS_LAZY_INIT = 0x40
    FLAGS_TWOLEVEL = 0x80
    FLAGS_FORCE_FLAT = 0x100
    FLAGS_NOMULTIDEFS = 0x200
    FLAGS_NOFIXPREBINDING = 0x400
    FLAGS_PREBINDABLE = 0x800
    FLAGS_ALLMODSBOUND = 0x1000
    FLAGS_SUBSECTIONS_VIA_SYMBOLS = 0x2000
    FLAGS_CANONICAL = 0x4000
    FLAGS_WEAK_DEFINES = 0x8000
    FLAGS_BINDS_TO_WEAK = 0x10000
    FLAGS_ALLOW_STACK_EXECUTION = 0x20000
    FLAGS_ROOT_SAFE = 0x40000
    FLAGS_SETUID_SAFE = 0x80000
    FLAGS_NO_REEXPORTED_DYLIBS = 0x100000
    FLAGS_PIE = 0x200000
    FLAGS_DEAD_STRIPPABLE_DYLIB = 0x400000
    FLAGS_HAS_TLV_DESCRIPTORS = 0x800000
    FLAGS_NO_HEAP_EXECUTION = 0x1000000

    def __init__(self, stream: io.RawIOBase):
        self.magic = stream.read(MACHO_UINT32)
        self.cputype = 0
        self.cpusubtype = 0
        self.filetype = 0
        self.ncmds = 0
        self.sizeofcmds = 0
        self.flags = 0
        self.reserved = 0

        if self.wordsz == 32:
            self.__parse32(stream, self.endianness)
        else:
            self.__parse64(stream, self.endianness)

    def __str__(self):
        return '\n'.join(['Mach-O HEADER',
                          'Magic:                       0x%02x',
                          'CPU type:                    %s',
                          'CPU subtype:                 {cpusubtype}',
                          'Filetype:                    %s',
                          'Number of commands:          {ncmds}',
                          'Size of commands:            {sizeofcmds} bytes',
                          'Flags:                       {flags:#x} %s']) \
                   .format(**self.__dict__) % (
                   int.from_bytes(self.magic, self.endianness),
                   self.cputype_str(),
                   self.filetype_str(),
                   self.flags_str())

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

    @property
    def wordsz(self):
        if self.magic == MACHO_MAGIC32 or self.magic == MACHO_CIGAM32:
            return 32
        elif self.magic == MACHO_MAGIC64 or self.magic == MACHO_CIGAM64:
            return 64
        raise TypeError("Not a valid MachO")

    def cputype_str(self):
        val = {-1: "any",
               1: "VAX",
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
        val = {MachOHeader.FLAGS_NOUNDEFS: "NOUNDEFS",
               MachOHeader.FLAGS_INCRLINK: "INCRLINK",
               MachOHeader.FLAGS_DYLDLINK: "DYLDLINK",
               MachOHeader.FLAGS_BINDATLOAD: "BINDATLOAD",
               MachOHeader.FLAGS_PREBOUND: "PREBOUND",
               MachOHeader.FLAGS_SPLIT_SEGS: "SPLIT_SEGS",
               MachOHeader.FLAGS_LAZY_INIT: "LAZY_INIT",
               MachOHeader.FLAGS_TWOLEVEL: "TWOLEVEL",
               MachOHeader.FLAGS_FORCE_FLAT: "FORCE_FLAT",
               MachOHeader.FLAGS_NOMULTIDEFS: "NOMULTIDEFS",
               MachOHeader.FLAGS_NOFIXPREBINDING: "NOFIXPREBINDING",
               MachOHeader.FLAGS_PREBINDABLE: "PREBINDABLE",
               MachOHeader.FLAGS_ALLMODSBOUND: "ALLMODSBOUND",
               MachOHeader.FLAGS_SUBSECTIONS_VIA_SYMBOLS: "SUBSECTIONS_VIA_SYMBOLS",
               MachOHeader.FLAGS_CANONICAL: "CANONICAL",
               MachOHeader.FLAGS_WEAK_DEFINES: "WEAK_DEFINES",
               MachOHeader.FLAGS_BINDS_TO_WEAK: "BINDS_TO_WEAK",
               MachOHeader.FLAGS_ALLOW_STACK_EXECUTION: "ALLOW_STACK_EXECUTION",
               MachOHeader.FLAGS_ROOT_SAFE: "ROOT_SAFE",
               MachOHeader.FLAGS_SETUID_SAFE: "SETUID_SAFE",
               MachOHeader.FLAGS_NO_REEXPORTED_DYLIBS: "NO_REEXPORTED_DYLIBS",
               MachOHeader.FLAGS_PIE: "PIE",
               MachOHeader.FLAGS_DEAD_STRIPPABLE_DYLIB: "DEAD_STRIPPABLE_DYLIB",
               MachOHeader.FLAGS_HAS_TLV_DESCRIPTORS: "HAS_TLV_DESCRIPTORS",
               MachOHeader.FLAGS_NO_HEAP_EXECUTION: "NO_HEAP_EXECUTION"}

        for key in val:
            if self.flags & key == key:
                retval.append(val[key])
        return " | ".join(retval)


class MachOSegment(object):
    SEGNAME_SIZE = 16

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

    def __init__(self, stream: io.RawIOBase, header: MachOHeader):
        self.cmd = 0
        self.cmdsize = 0
        self.segname = str()
        self.vmaddr = 0
        self.vmsize = 0
        self.fileoff = 0
        self.filesize = 0
        self.maxprot = 0
        self.initprot = 0
        self.nsects = 0
        self.flags = 0

        if header.wordsz == 32:
            self.__parse32(stream, header.endianness)
        else:
            self.__parse64(stream, header.endianness)

    def __parse32(self, stream: io.RawIOBase, endianness):
        self.cmd = int.from_bytes(stream.read(MACHO_UINT32), endianness)
        self.cmdsize = int.from_bytes(stream.read(MACHO_UINT32), endianness)
        if self.cmd == 0x01:
            self.segname = stream.read(MachOSegment.SEGNAME_SIZE).decode("ascii")
            self.vmaddr = int.from_bytes(stream.read(MACHO_UINT32), endianness)
            self.vmsize = int.from_bytes(stream.read(MACHO_UINT32), endianness)
            self.fileoff = int.from_bytes(stream.read(MACHO_UINT32), endianness)
            self.filesize = int.from_bytes(stream.read(MACHO_UINT32), endianness)
            self.maxprot = int.from_bytes(stream.read(MACHO_VM_PROT), endianness)
            self.initprot = int.from_bytes(stream.read(MACHO_VM_PROT), endianness)
            self.nsects = int.from_bytes(stream.read(MACHO_UINT32), endianness)
            self.flags = int.from_bytes(stream.read(MACHO_UINT32), endianness)

    def __parse64(self, stream: io.RawIOBase, endianness):
        pass


class MachO(object):
    def __init__(self, stream: io.RawIOBase):
        self.header = MachOHeader(stream)
        self.segments = []

        # Segments
        seek = stream.tell()
        for _ in range(self.header.ncmds):
            seg = MachOSegment(stream, self.header)
            self.segments.append(seg)
            seek += seg.cmdsize
            stream.seek(seek)

    def __str__(self):
        return str(self.header)

    @staticmethod
    def verify(file: io.RawIOBase):
        s_pos = file.tell()
        magic = file.read(MACHO_UINT32)
        file.seek(s_pos)
        return magic == MACHO_MAGIC32 or magic == MACHO_CIGAM32 or magic == MACHO_MAGIC64 or magic == MACHO_CIGAM64
