"""
Pcap-ng file scanner
"""

from pcapng.structs import (
    read_int, read_block_data, read_section_header, SECTION_HEADER_MAGIC,
    Options)
import pcapng.blocks as blocks
from pcapng.exceptions import StreamEmpty


class FileScanner(object):
    """
    Scanner for pcap-ng files.

    Can be iterated to get blocks from the file.

    :param stream: Stream from which to read data
    """

    def __init__(self, stream):
        self.stream = stream
        self.current_section = None
        self.endianness = '='

    def __iter__(self):
        while True:
            try:
                yield self._read_next_block()
            except StreamEmpty:
                return

    def _read_next_block(self):
        block_type = self._read_int(32, False)

        if block_type == SECTION_HEADER_MAGIC:
            block = self._read_section_header()
            self.current_section = block
            self.endianness = block.endianness
            return block

        if self.current_section is None:
            raise ValueError('File not starting with a proper section header')

        block = self._read_block(block_type)
        if isinstance(block, blocks.InterfaceDescription):
            self.current_section.interfaces.append(block)
        return block

    def _read_section_header(self):
        """
        Section information headers are special blocks in that they
        modify the state of the FileScanner instance (to change current
        section / endianness)
        """

        section_info = read_section_header(self.stream)
        self.endianness = section_info['endianness']
        return blocks.SectionHeader(
            endianness=section_info['endianness'],
            version=section_info['version'],
            length=section_info['section_length'],
            options=Options(section_info['options_raw']))

    def _read_block(self, block_type):
        """
        Read the block payload and pass to the appropriate block constructor
        """
        data = read_block_data(self.stream, endianness=self.endianness)
        if block_type in blocks.KNOWN_BLOCKS:
            return blocks.KNOWN_BLOCKS[block_type](data)
        return blocks.UnknownBlock(block_type, data)

    def _read_int(self, size, signed=False):
        """
        Read an integer from the stream, using current endianness
        """
        return read_int(self.stream, size, signed=signed,
                        endianness=self.endianness)
