import argparse
import sys
from finder import search4cave
from elf import *
from macho import *

__version__ = "1.0.0"

WELCOME = """
                      /=============\\
                     /      | |      \\  
   ______                   | |     ______ _             __           
  / ____/____ _ _   __ ___  | |    / ____/(_)____   ____/ /___   _____
 / /    / __ `/| | / // _ \ | |   / /_   / // __ \ / __  // _ \ / ___/
/ /___ / /_/ / | |/ //  __/ | |  / __/  / // / / // /_/ //  __// /    
\____/ \__,_/  |___/ \___/  |_| /_/    /_//_/ /_/ \__,_/ \___//_/ v:%s"""


def main():
    parser = argparse.ArgumentParser(description="Dig in a binary to find all code caves")
    parser.add_argument("binary", help="Executable file")
    parser.add_argument("--size", help="Minimum size of a code cave, Default: 100", type=int, default=100)
    parser.add_argument("--bytes", help="Bytes to search, Default: 0x00", type=str, default="\x00")
    args = parser.parse_args()

    print("[*] Loading binary '%s'..." % args.binary, end="\n\n")

    try:
        stream = open(args.binary, "rb")
    except FileNotFoundError as err:
        print(err, file=sys.stderr)
        exit(-1)

    btype = load_binary(stream)

    if btype is None:
        print("Unsupported binary type")
        exit(-1)

    print(btype, end="\n\n")

    caves = search_by_type(stream, args.size, bytes(args.bytes.encode("ascii")), btype)

    print("[!] Caves found: %d" % len(caves), end="\n\n")
    for cave in caves:
        print(cave, end="\n\n")
    print("[*] Mining finished")


def load_binary(stream):
    if Elf.verify(stream):
        return Elf(stream)
    elif MachO.verify(stream):
        return MachO(stream)
    return None


def search_by_type(stream, cave_size, _bytes, btype):
    caves = []
    if isinstance(btype, Elf):
        elf: Elf = btype
        for section in elf.sections:
            stream.seek(section.sh_offset)
            info = "Type: %s, Flags: %s" % (section.type_str(), section.flags_str())
            caves += search4cave(stream, elf.get_section_name(section), section.sh_size, info, cave_size, 0, _bytes)
    elif isinstance(btype, MachO):
        macho: MachO = btype
        for segment in macho.segments:
            for section in segment.sections:
                stream.seek(section.offset)
                info = "%s [%s]" % (segment.initprot_str, segment.maxprot_str)
                caves += search4cave(stream, "%s.%s" % (section.segname, section.sectname), section.size, info,
                                     cave_size, section.addr, _bytes)

    return caves


if __name__ == "__main__":
    print(WELCOME % __version__, end='\n\n')
    main()
