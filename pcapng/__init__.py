# Library to parse pcap-ng file format
# See: http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html

from __future__ import print_function

import struct
from collections import namedtuple


LITTLE_ENDIAN = 1
BIG_ENDIAN = 2


# Block types
# ----------------------------------------

BLK_RESERVED = 0x00000000  # Reserved
BLK_INTERFACE = 0x00000001  # Interface description block
BLK_PACKET = 0x00000002  # Packet Block
BLK_PACKET_SIMPLE = 0x00000003  # Simple Packet block
BLK_NAME_RESOLUTION = 0x00000004  # Name Resolution Block
BLK_INTERFACE_STATS = 0x00000005  # Interface Statistics Block
BLK_ENHANCED_PACKET = 0x00000006  # Enhanced Packet Block

# IRIG Timestamp Block (requested by Gianluca Varenni
# <gianluca.varenni@cacetech.com>, CACE Technologies LLC)
BLK_IRIG_TIMESTAMP = 0x00000007

# Arinc 429 in AFDX Encapsulation Information Block
# (requested by Gianluca Varenni <gianluca.varenni@cacetech.com>,
# CACE Technologies LLC)
BLK_ARINC429 = 0x00000008

BLK_SECTION_HEADER = 0x0a0d0d0a  # Section Header Block

# Ranges of reserved blocks used to indicate corrupted file.
# Reserved. Used to detect trace files corrupted because
# of file transfers using the HTTP protocol in text mode.
BLK_RESERVED_CORRUPTED = [
    (0x0A0D0A00, 0x0A0D0AFF),
    (0x000A0D0A, 0xFF0A0D0A),
    (0x000A0D0D, 0xFF0A0D0D),
    (0x0D0D0A00, 0x0D0D0AFF),
]

# Byte order magic numbers
ORDER_MAGIC_LE = 0xA1B2C3D4
ORDER_MAGIC_BE = 0xD4C3B2A1

SIZE_NOTSET = 0xffffffffffffffff  # 64bit "-1"


GenericBlock = namedtuple(
    'GenericBlock', "block_type,block_size,block_body")

SectionHeader = namedtuple(
    'SectionHeader',
    'block_size,endianness,version,section_length,options')

Interface = namedtuple(
    'Interface',
    'block_type,block_size,block_body,link_type,snaplen,options')


class PCAPNG_Reader(object):
    _endianness = None
    _latest_section = None
    _latest_interface = None

    def __init__(self, fp):
        self._fp = fp

    def read_block(self):
        """Read a block from the file"""

        _type = self._fp.read(4)

        if self._endianness is None:
            # We are at the beginning of the file.
            # The next block we are going to read is a
            # section header.
            _type = struct.unpack('<I', _type)
            if _type != BLK_SECTION_HEADER:
                raise ValueError(
                    "Invalid file: expected section header 0x{0:08x}, "
                    "got 0x{1:08x}".format(BLK_SECTION_HEADER, _type))

            # Read the actual section header
            return self._read_section_header()

        # Check the block type and dispatch parsing
        # -------------------------------------------

        blk = self._read_block_generic()
        return self._parse_block(blk)

    def _read_block_generic(self):
        """Read a complete block, including its type"""

        _fldlen = 12
        _blk_type = self._read_u32()
        _totlen = self._read_u32()

        # Read payload
        _payload_len = _totlen - _fldlen
        if _payload_len < 0:
            raise ValueError("Invalid block size!")
        _payload = self._read(_payload_len)

        # Check size at block end
        _totlen2 = self._read_u32()
        if _totlen2 != _totlen:
            raise ValueError("Mismatching block size: start was {0}, "
                             "end is {1}".format(_totlen, _totlen2))

        return GenericBlock(
            block_type=_blk_type,
            block_size=_totlen,
            block_body=_payload)

    def _read_section_header(self):
        # (4 bytes: block type) [already read]
        # 4 bytes: total length
        # 4 bytes: byte_order_magic
        # 2 bytes: major version; 2 bytes: minor version
        # 8 bytes: section length (for traversing) (-1 for "unknown")
        # ...options for the remaining length...
        # 4 bytes: total length (again)

        # todo: we need to recompose stuff a bit and pass to
        #       _parse_section_header()

        _fixed_fields_size = sum((4, 4, 4, 2, 8, 4))

        _totlen = self._fp.read(4)
        _bo_magic = struct.unpack('<I', self._fp.read(4))
        if _bo_magic == ORDER_MAGIC_LE:
            self._endianness = LITTLE_ENDIAN
        elif _bo_magic == ORDER_MAGIC_BE:
            self._endianness = BIG_ENDIAN
        else:
            raise ValueError("Invalid byte order magic: expected 0x{0:08x} "
                             "(or 0x{1:08x}, got 0x{2:08x})"
                             .format(ORDER_MAGIC_LE, ORDER_MAGIC_BE,
                                     _bo_magic))
        _totlen = self._unpack('I', _totlen)

        # Check that size is ok..
        if _totlen < _fixed_fields_size:
            raise ValueError("Section length is too small!")

        # Read version number
        _major, _minor = self._unpack('HH', self._fp.read(4))

        # Read section length
        _section_length = self._unpack('Q', self._fp.read(8))

        # Time to read the options
        _options_size = _totlen - _fixed_fields_size
        _options_data = self._fp.read(_options_size)

        # Check the closing size
        _totlen2 = self._read_u32()
        if _totlen2 != _totlen:
            raise ValueError("Mismatching block size: start was {0}, "
                             "end is {1}".format(_totlen, _totlen2))

        # Prepare the block object to be returned
        sh = SectionHeader(
            block_size=_totlen,
            endianness=self._endianness,
            version=(_major, _minor),
            section_length=_section_length,
            options=self._parse_options(_options_data))

        self._latest_section = sh  # just in case..
        self._latest_interface = None  # interfaces are per-section!

        return sh

    def _parse_block(self, blk):
        """Convert a generic block in something else, if possible"""

        _type = blk.block_type

        if _type == BLK_INTERFACE:
            return self._parse_block_interface(blk)

        if _type == BLK_PACKET:
            return self._parse_block_packet(blk)

        if _type == BLK_PACKET_SIMPLE:
            return self._parse_block_packet_simple(blk)

        if _type == BLK_NAME_RESOLUTION:
            return self._parse_block_name_resolution(blk)

        if _type == BLK_INTERFACE_STATS:
            return self._parse_block_interface_stats(blk)

        if _type == BLK_ENHANCED_PACKET:
            return self._parse_block_enhanced_packet(blk)

        if _type == BLK_SECTION_HEADER:
            return self._parse_section_header(blk)

        return blk

    def _parse_block_interface(self, blk):
        _lnktype = self._unpack('I', blk.block_body[:2])
        # ignore [2:4] -> reserved block
        _snaplen = self._unpack('I', blk.block_body[4:8])
        _options_raw = blk.block_body[8:]
        _options = self._parse_options(_options_raw)

        return Interface(
            *blk, link_type=_lnktype, snaplen=_snaplen, options=_options)

    def _parse_block_packet(self, blk):
        return blk

    def _parse_block_packet_simple(self, blk):
        return blk

    def _parse_block_enhanced_packet(self, blk):
        return blk

    def _parse_block_name_resolution(self, blk):
        return blk

    def _parse_block_interface_stats(self, blk):
        return blk

    def _parse_section_header(self, blk):
        return blk

    def _parse_options(self, data):
        return data

    # ------------------------------------------------------------
    #   Struct parsing stuff
    # ------------------------------------------------------------

    def _unpack(self, fmt, data):
        if self._endianness == LITTLE_ENDIAN:
            fmt = '<' + fmt
        elif self._endianness == BIG_ENDIAN:
            fmt = '>' + fmt
        else:
            raise ValueError("Unspecified endianness!")
        return struct.unpack(fmt, data)

    def _read(self, fmt, size):
        return self._unpack(fmt, self._fp.read(size))

    def _read_i16(self):
        return self._read('h', 2)

    def _read_u16(self):
        return self._read('H', 2)

    def _read_i32(self):
        return self._read('i', 4)

    def _read_u32(self):
        return self._read('I', 4)

    def _read_i64(self):
        return self._read('q', 8)

    def _read_u64(self):
        return self._read('Q', 8)


if __name__ == '__main__':
    import sys
    rdr = PCAPNG_Reader(sys.stdin)
    while True:
        packet = rdr.read_block()
        print(repr(packet))
