"""
Pcap-ng file scanner
"""

import binascii
import logging
import struct

from pcapng.structs import (
    read_int, read_block, read_section_header, SECTION_HEADER_MAGIC)
import pcapng.blocks as blocks
from pcapng.exceptions import StreamEmpty


class FileScanner(object):
    """
    Scanner for pcap-ng files.

    Can be iterated to get blocks from the file.

    :param stream: Stream from which to read data
    """

    def __init__(self, stream):
        self.stream = None
        self.current_section = None
        self.endianness = '='

    def __iter__(self):
        return self  # The object itself is iterable

    def next(self):
        try:
            yield self._read_next_block()
        except StreamEmpty:
            raise StopIteration('End of stream reached')

    def _read_next_block(self):
        block_type = self._read_int(32, False)

        if block_type == SECTION_HEADER_MAGIC:
            block = self._read_section_header()
            self.current_section = block
            self.endianness = block.endianness
            return block

        return self._read_block(block_type)

    def _read_section_header(self):
        section_info = read_section_header(self.stream)
        self.endianness = section_info['endianness']
        return blocks.SectionHeader(
            endianness=section_info['endianness'],
            version=section_info['version'],
            length=section_info['section_length'],
            options=blocks.Options(section_info['options_raw']))

    def _read_block(self, block_type):
        pass

    def _read_int(self, size, signed=False):
        return read_int(self.stream, size, signed=signed,
                        endianness=self.endianness)
        pass
