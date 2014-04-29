# Library to parse pcap-ng file format
# See: http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html

from __future__ import print_function

import binascii
import logging
import struct
from collections import namedtuple


logger = logging.getLogger(__name__)


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
ORDER_MAGIC_LE = 0x1a2b3c4d
ORDER_MAGIC_BE = 0x4d3c2b1a

SIZE_NOTSET = 0xffffffffffffffff  # 64bit "-1"


def _repr_nt(nt):
    MAX_VLEN = 30
    ELLPS = '...'

    name = nt.__class__.__name__
    fld_reprs = []
    for fld in nt._fields:
        value = repr(getattr(nt, fld))

        if len(value) > MAX_VLEN:
            # We want to cut in two parts of (MAX_VLEN-3)/2 length
            vl = MAX_VLEN - len(ELLPS)
            p1l = (vl // 2) + (vl % 2)
            p2l = vl // 2
            value = ''.join((value[:p1l], ELLPS, value[-p2l:]))

        fld_reprs.append((fld, value))
    return '{0}({1})'.format(name, ', '.join('='.join(kv) for kv in fld_reprs))


class GenericBlock(namedtuple(
        'GenericBlock', 'block_type,block_size,block_body')):
    def __repr__(self):
        return _repr_nt(self)


class SectionHeader(namedtuple(
        'SectionHeader',
        'block_type,block_size,block_body,'
        'byte_order_magic,version,section_length,options')):
    def __repr__(self):
        return _repr_nt(self)


class Interface(namedtuple(
        'Interface',
        'block_type,block_size,block_body,'
        'link_type,snaplen,options')):
    def __repr__(self):
        return _repr_nt(self)


class PCAPNG_Reader(object):
    _endianness = None
    _current_section = None
    _current_interfaces = None

    def __init__(self, fp):
        self._fp = fp

    def read_block(self):
        raw_blk = self._read_next_block()
        blk = self._parse_block(raw_blk)

        if isinstance(blk, SectionHeader):
            # Keep away the latest (current) section
            self._current_section = blk
            self._current_interfaces = []

        elif isinstance(blk, Interface):
            # Keep interfaces for this section
            self._current_interfaces.append(blk)

        if type(blk) == GenericBlock:
            logger.warning("Unrecognised block type 0x{0:08x} was not parsed"
                           .format(blk.block_type))

        return blk

    def _read_next_block(self):
        logger.debug("---- Reading next block from input ----")

        assert self._fp.tell() % 4 == 0   # !

        # todo: handle EOF properly!

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

        return GenericBlock(
            block_type=block_type,
            block_size=_totlen,
            block_body=_payload)

    def _read_block_section_header(self, block_type):
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
            self._endianness = LITTLE_ENDIAN

        elif _bo_magic == ORDER_MAGIC_BE:  # nope, was BE!
            logger.debug('    -> section is Big Endian')
            self._endianness = BIG_ENDIAN

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

        return GenericBlock(
            block_type=block_type,
            block_size=_totlen,
            block_body=_payload)

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
            return self._parse_block_section_header(blk)

        return blk

    def _parse_block_interface(self, blk):
        logger.debug("Parsing an interface block")

        _lnktype = self._unpack('H', blk.block_body[:2])
        logger.debug('    link type: 0x{0:08x}'.format(_lnktype))
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
        logger.debug('Reading a name resolution block')
        return blk

    def _parse_block_interface_stats(self, blk):
        logger.debug('Reading an interface stats block')
        return blk

    def _parse_block_section_header(self, blk):
        logger.debug('Reading a section header block')

        # 4 bytes: byte_order_magic
        # 2 bytes: major version; 2 bytes: minor version
        # 8 bytes: section length (for traversing) (-1 for "unknown")
        # ...options for the remaining length...

        bo_magic = self._unpack('I', blk.block_body[:4])
        assert bo_magic == ORDER_MAGIC_LE  # should be fixed by now!
        major, minor = self._unpack('HH', blk.block_body[4:8])

        section_length = self._unpack('q', blk.block_body[8:16])

        options_data = blk.block_body[16:]
        options = self._parse_options(options_data)

        return SectionHeader(
            *blk, byte_order_magic=bo_magic, version=(major, minor),
            section_length=section_length, options=options)

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
            # raise ValueError("Unspecified endianness!")
            fmt = '=' + fmt  # todo: should we warn the user?

        unpacked = struct.unpack(fmt, data)
        if len(unpacked) == 1:
            assert len(fmt) == 2  # The user knew!
            return unpacked[0]
        return unpacked

    def _padded_read(self, size):
        """
        Read up to size bytes from fp; read and ignore bytes
        necessary to align to 32bit blocks..
        """

        logger.debug(">>> reading {0} bytes".format(size))
        data = self._fp.read(size)

        _padding = (4 - size % 4) % 4
        if _padding > 0:
            logger.debug("    padding bytes: {0}".format(_padding))
            self._fp.read(_padding)

        if self._fp.tell() % 4 != 0:
            raise RuntimeError(
                "Somehow we got on an invalid position in the file "
                "(not multiple of four). Something is broken.")

        return data

    def _read_packed(self, fmt, size):
        return self._unpack(fmt, self._fp.read(size))

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
