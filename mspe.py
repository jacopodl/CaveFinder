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


# https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
# https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-tools/widl/include/winnt.h
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx#file_headers
class Pe(object):
    def __init__(self, stream: io.RawIOBase):
        self.dos_header = DosHeader(stream)

        # Read NT signature
        stream.seek(self.dos_header.e_lfanew)
        self.nt_signature = stream.read(MS_DWORD)
        if PE_CIGAM not in self.nt_signature and PE_MAGIC not in self.nt_signature:
            raise TypeError("Not a valid PE (Invalid NT signature)")

    @staticmethod
    def verify(file: io.RawIOBase):
        s_pos = file.tell()
        magic = file.read(MS_WORD)
        file.seek(s_pos)
        return magic == MZ_MAGIC or magic == MZ_CIGAM
