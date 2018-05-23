import argparse
import os
import sys

from cavefinder.finder import search4cave, verifycave
from cavefinder.support.elf import *
from cavefinder.support.macho import *
from cavefinder.support.mspe import *

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
    parser.add_argument("--size", help="minimum size of a code cave, default: 100", type=int, default=100)
    parser.add_argument("--byte", help="byte to search, default: 0x00", type=str, default="0x00")
    parser.add_argument("--payload", help="file with payload to be injected", type=str, metavar="<file_name>")
    parser.add_argument("--addr", help="address where to inject the payload", type=str, metavar="<address>", default=0)
    parser.add_argument("binary", help="executable file")
    args = parser.parse_args()

    print(WELCOME % __version__, end='\n\n')
    print("[*] Loading binary '%s'..." % args.binary, end="\n\n")

    stream = open_file(args.binary, args.payload is not None)
    btype = load_binary(stream)

    if btype is None:
        print("Unsupported binary type")
        exit(-1)

    print(btype, end="\n\n")

    if args.payload is None:
        caves = search_by_type(stream, args.size, bytes([int(args.byte.encode("ascii"), 16)]), btype)
        print("[!] Caves found: %d" % len(caves), end="\n\n")
        for cave in caves:
            print(cave, end="\n\n")
        print("[*] Mining finished")
    else:
        addr_base = int(args.addr.encode("ascii"), 16)
        payload = open_file(args.payload)
        paysize = os.path.getsize(args.payload)
        print("[*] Injecting %s (size %d bytes) into %s..." % (args.payload, paysize, args.binary))

        stream.seek(addr_base)
        if not verifycave(stream, paysize, bytes([int(args.byte.encode("ascii"), 16)])):
            print("Payload is too big for %s@0x%02x, aborted!" % (args.binary, addr_base), file=sys.stderr)
            exit(-1)

        stream.write(payload.read())
        payload.close()
        print("[*] Finished")

    stream.close()


def open_file(file: str, writable=False) -> io.RawIOBase:
    stream: io.RawIOBase = None
    try:
        stream = open(file, "rb" if not writable else "r+b")
    except FileNotFoundError as err:
        print(err, file=sys.stderr)
        exit(-1)
    return stream


def load_binary(stream):
    if Elf.verify(stream):
        return Elf(stream)
    elif MachO.verify(stream):
        return MachO(stream)
    elif Pe.verify(stream):
        return Pe(stream)
    return None


def search_by_type(stream, cave_size, _bytes, btype):
    caves = []
    if isinstance(btype, Elf):
        elf: Elf = btype
        for section in elf.sections:
            stream.seek(section.sh_offset)
            info = "Type: %s, Flags: %s" % (section.type_str(), section.flags_str())
            caves += search4cave(stream, elf.get_section_name(section), section.sh_size, info, cave_size,
                                 section.sh_addr, _bytes)
    elif isinstance(btype, MachO):
        macho: MachO = btype
        for segment in macho.segments:
            for section in segment.sections:
                stream.seek(section.offset)
                info = "%s [%s]" % (segment.initprot_str, segment.maxprot_str)
                caves += search4cave(stream, "%s.%s" % (section.segname, section.sectname), section.size, info,
                                     cave_size, section.addr, _bytes)
    elif isinstance(btype, Pe):
        pe: Pe = btype
        image_base = pe.pe_header.optional_header.image_base
        for section in pe.sections:
            stream.seek(section.ptr_rawdata)
            caves += search4cave(stream, section.name, section.size_rawdata, None, cave_size,
                                 image_base + section.virtual_addr, _bytes)

    return caves


if __name__ == "__main__":
    main()
