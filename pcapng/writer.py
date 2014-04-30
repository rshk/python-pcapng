from __future__ import print_function

import binascii
import io
import logging
import struct

from .objects import (
    GenericBlock, SectionHeader, Interface, InterfaceStatistics,
    Packet, SimplePacket, EnhancedPacket, NameResolution)
from .constants import (
    ENDIAN_LITTLE, ENDIAN_BIG, ORDER_MAGIC_BE, ORDER_MAGIC_LE)
from .constants.block_types import (
    BLK_INTERFACE, BLK_PACKET, BLK_SECTION_HEADER, BLK_PACKET_SIMPLE,
    BLK_ENHANCED_PACKET, BLK_NAME_RESOLUTION, BLK_INTERFACE_STATS)

logger = logging.getLogger(__name__)


class PcapngWriter(object):
    def __init__(self, fp):
        self._fp = fp
        self._current_section = None

    def write_block(self, blk):
        """Write a block to the stream"""

        if isinstance(blk, SectionHeader):
            self._current_section = blk

        if self._current_section is None:
            raise ValueError(
                "Trying to write a block w/o a section header!")

        packed = self._pack_block(blk)
        self._write_block(packed.block_type, packed.contents)

    def _pack_block(self, blk):
        if isinstance(blk, SectionHeader):
            return self._pack_section_header(blk)

        if isinstance(blk, Interface):
            pass

        if isinstance(blk, InterfaceStatistics):
            pass

        if isinstance(blk, Packet):
            pass

        if isinstance(blk, SimplePacket):
            pass

        if isinstance(blk, EnhancedPacket):
            pass

        if isinstance(blk, NameResolution):
            pass

    def _pack_section_header(self, blk):
        pass

    def _pack_options(self):
        pass

    def _write_block(self, block_type, block_body):
        self._write('I', block_type)
        self._write('I', len(block_body))
        self._fp.write(block_body)
        self._write('I', len(block_body))

    # ------------------------------------------------------------
    # Low-level functions to write structs
    # ------------------------------------------------------------

    def _write(self, fmt, data):
        self._fp.write(self._pack(fmt, data))

    def _pack(self, fmt, data):
        if not isinstance(data, (list, tuple)):
            data = (data,)

        packed = struct.pack(fmt, data)
        return packed

    def _padded_write(self, data, fp=None):
        """
        Write data to fp, followed by null bytes to fill remaining
        space for 32bit alignment.
        """
        _padding = (4 - (len(data) % 4)) % 4
        fp.write(data)
        fp.write('\x00' * _padding)
