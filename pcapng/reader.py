from __future__ import print_function

import binascii
import logging
import struct

from .objects import (
    RawBlock, SectionHeader, Interface, Packet, SimplePacket,
    EnhancedPacket, NameResolution, InterfaceStatistics)
from .constants import (
    ENDIAN_LITTLE, ENDIAN_BIG, ORDER_MAGIC_BE, ORDER_MAGIC_LE)
from .constants.block_types import (
    BLK_INTERFACE, BLK_PACKET, BLK_SECTION_HEADER, BLK_PACKET_SIMPLE,
    BLK_ENHANCED_PACKET, BLK_NAME_RESOLUTION, BLK_INTERFACE_STATS)

from .utils import aligned_read

logger = logging.getLogger(__name__)


class PcapngReader(object):
    """Reader for the PCAP-NG format"""

    _endianness = None
    _current_section = None
    _current_interfaces = None

    def __init__(self, fp):
        self._fp = fp

    def __iter__(self):
        try:
            while True:
                yield self._read_block()
        except EOFError:
            return

    def _read_block(self):
        raw_blk = self._read_next_block()
        blk = self._parse_block(raw_blk)

        if isinstance(blk, SectionHeader):
            # Keep away the latest (current) section
            self._current_section = blk
            self._current_interfaces = []

        else:
            if isinstance(blk, Interface):
                # Keep interfaces for this section
                self._current_interfaces.append(blk)

            blk._section = self._current_section

            # Add reference to the interface
            if hasattr(blk, 'interface_id'):
                try:
                    blk._interface = self._current_interfaces[blk.interface_id]
                except IndexError:
                    pass

        if type(blk) == RawBlock:
            logger.warning(
                "Unrecognised block type 0x{0:08x} was not parsed"
                .format(blk.block_type))

        return blk

    def _read_next_block(self):
        logger.debug("---- Reading next block from input ----")

        assert self._fp.tell() % 4 == 0   # !

        block_type = self._read_u32()

        if block_type == BLK_SECTION_HEADER:
            # We are going to treat this one in a custom way
            # as section headers change endianness..
            return self._read_block_section_header(block_type)

        # We are going to treat this one the usual way
        return self._read_block_generic(block_type)

    def _read_block_generic(self, block_type):
        logger.debug("*** Reading a generic block")

        if self._endianness is None:
            raise ValueError(
                "Cannot read a generic block with no endianness set. "
                "Was expecting a section header block!")

        _fldlen = 12
        _totlen = self._read_u32()
        logger.debug("    block type: 0x{0:08x}".format(block_type))
        logger.debug("    block length: {0} (0x{0:08x})".format(_totlen))

        # Read payload
        _payload_len = _totlen - _fldlen
        if _payload_len < 0:
            raise ValueError("Invalid block size!")
        _payload = self._padded_read(_payload_len)
        logger.debug("    payload length: {0}".format(_payload_len))

        # Check size at block end
        _totlen2 = self._read_u32()
        if _totlen2 != _totlen:
            raise ValueError("Mismatching block size: start was {0}, "
                             "end is {1}".format(_totlen, _totlen2))

        return RawBlock(
            block_type=block_type,
            contents=_payload)

    def _read_block_section_header(self, block_type):
        """
        Reading a "section header" block is quite a special case,
        as it is used to set endianness for the block itself
        and for following blocks in the file.

        For this reason, we need to read the "byte order magic"
        block from inside the packet and use it to set endianness,
        then we can normally parse the block.

        Note that we cannot just read the block then backwards seek
        as there is no guarantee the input file-like object
        supports seeking! (might be a stream..).
        """

        # ------------------------------------------------------------
        # (4 bytes: block type) [already read]
        # 4 bytes: total length
        # 4 bytes: byte_order_magic
        # 2 bytes: major version; 2 bytes: minor version
        # 8 bytes: section length (for traversing) (-1 for "unknown")
        # ...options for the remaining length...
        # 4 bytes: total length (again)
        # ------------------------------------------------------------

        logger.debug('*** Reading a section header')

        _totlen_raw = self._fp.read(4)  # keep this away for later
        logger.debug('    raw block length: {0}'
                     .format(binascii.hexlify(_totlen_raw)))

        # Read the magic number and use to determine the byte order
        # ------------------------------------------------------------

        _bo_magic_raw = self._fp.read(4)
        _bo_magic = struct.unpack('<I', _bo_magic_raw)[0]  # assume LE
        logger.debug('    magic number: 0x{0:08x}'.format(_bo_magic))

        if _bo_magic == ORDER_MAGIC_LE:  # yes, it was LE!
            logger.debug('    -> section is Little Endian')
            self._endianness = ENDIAN_LITTLE

        elif _bo_magic == ORDER_MAGIC_BE:  # nope, was BE!
            logger.debug('    -> section is Big Endian')
            self._endianness = ENDIAN_BIG

        else:
            raise ValueError(
                "Invalid byte order magic: expected 0x{0:08x} "
                "(or 0x{1:08x}, got 0x{2:08x})"
                .format(ORDER_MAGIC_LE, ORDER_MAGIC_BE, _bo_magic))

        # Now that we know the endianness we can proceed as usual
        # ------------------------------------------------------------

        _totlen = self._unpack('I', _totlen_raw)
        logger.debug('    block length: {0}'.format(_totlen))

        # Ok, we can read the block etc. as usual..
        _payload_offset = 4 + 4 + 4  # We already read type, length, byteorder
        _payload_length = _totlen - _payload_offset - 4  # trailing TL
        logger.debug("    payload length: {0}".format(_payload_length))

        _payload = _bo_magic_raw + self._padded_read(_payload_length)

        # Check size at block end
        _totlen2 = self._read_u32()
        if _totlen2 != _totlen:
            raise ValueError("Mismatching block size: start was {0}, "
                             "end is {1}".format(_totlen, _totlen2))

        return RawBlock(
            block_type=block_type,
            contents=_payload)

    def _parse_block(self, blk):
        """Convert a generic block in something else, if possible"""

        _type = blk.block_type

        if _type == BLK_SECTION_HEADER:
            logger.debug('Parsing a section header block')
            return SectionHeader.unpack(blk.contents, self._endianness)

        if _type == BLK_INTERFACE:
            logger.debug("Parsing an interface block")
            return Interface.unpack(blk.contents, self._endianness)

        if _type == BLK_PACKET:
            logger.debug('Parsing a packet block')
            return Packet.unpack(blk.contents, self._endianness)

        if _type == BLK_PACKET_SIMPLE:
            logger.debug('Parsing a simple packet block')
            return SimplePacket.unpack(blk.contents, self._endianness)

        if _type == BLK_ENHANCED_PACKET:
            logger.debug('Parsing an enhanced packet block')
            return EnhancedPacket.unpack(blk.contents, self._endianness)

        if _type == BLK_NAME_RESOLUTION:
            logger.debug('Parsing a name resolution block')
            return NameResolution.unpack(blk.contents, self._endianness)

        if _type == BLK_INTERFACE_STATS:
            logger.debug('Parsing an interface stats block')
            return InterfaceStatistics.unpack(blk.contents, self._endianness)

        return blk

    # ------------------------------------------------------------
    #   Struct parsing stuff
    # ------------------------------------------------------------

    def _unpack(self, fmt, data):
        if self._endianness == ENDIAN_LITTLE:
            fmt = '<' + fmt
        elif self._endianness == ENDIAN_BIG:
            fmt = '>' + fmt
        else:
            # raise ValueError("Unspecified endianness!")
            fmt = '=' + fmt  # todo: should we warn the user?

        unpacked = struct.unpack(fmt, data)
        if len(unpacked) == 1:
            assert len(fmt) == 2  # The user knew!
            return unpacked[0]
        return unpacked

    def _padded(self, n, to):
        return n + ((to - (n % to)) % to)

    def _padded_read(self, size, fp=None):
        if fp is None:
            fp = self._fp
        return aligned_read(fp, size, bs=4)

    def _read_packed(self, fmt, size):
        data = self._fp.read(size)
        if len(data) < size:
            raise EOFError("We reached end of file!")
        return self._unpack(fmt, data)

    def _read_i16(self):
        return self._read_packed('h', 2)

    def _read_u16(self):
        return self._read_packed('H', 2)

    def _read_i32(self):
        return self._read_packed('i', 4)

    def _read_u32(self):
        return self._read_packed('I', 4)

    def _read_i64(self):
        return self._read_packed('q', 8)

    def _read_u64(self):
        return self._read_packed('Q', 8)
