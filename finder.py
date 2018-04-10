import io


class MiningResult(object):
    def __init__(self):
        self.name = str()
        self.cave_begin = 0
        self.cave_end = 0
        self.cave_size = 0
        self.virtaddr = 0
        self.info = None

    def __str__(self):
        return "\n".join(["Section name:       {name}",
                          "Cave begin:         {cave_begin} - {cave_begin:#x}",
                          "Cave end:           {cave_end} - {cave_end:#x}",
                          "Cave size:          {cave_size}",
                          "Virtaddr:           {virtaddr} - {virtaddr:#x}",
                          "info:               {info}"]).format(**self.__dict__)


def search4cave(stream: io.RawIOBase, section_name: str, section_size: int, section_info, cave_size: int, virtaddr: int,
                _bytes: bytes):
    caves = []
    byte_count = 0

    offset = stream.tell()

    while section_size > 0:
        rb = stream.read(1)
        section_size -= 1

        if _bytes not in rb:
            if byte_count >= cave_size:
                mr = MiningResult()
                mr.name = section_name
                mr.cave_begin = offset - byte_count
                mr.cave_end = offset
                mr.cave_size = byte_count
                mr.virtaddr = virtaddr + mr.cave_begin
                mr.info = section_info
                caves.append(mr)
            byte_count = 0
            continue
        byte_count += 1
        offset += 1

    return caves
