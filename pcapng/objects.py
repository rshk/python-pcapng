"""
Objects used to represent blocks.
"""

from collections import MutableMapping, namedtuple
import struct
from io import BytesIO

from .constants.block_types import (
    BLK_SECTION_HEADER, BLK_PACKET_SIMPLE, BLK_PACKET, BLK_ENHANCED_PACKET,
    BLK_INTERFACE, BLK_INTERFACE_STATS, BLK_NAME_RESOLUTION)
from .constants import ENDIAN_NATIVE, ENDIAN_LITTLE, ENDIAN_BIG
from .constants.options import OPT_ENDOFOPT
from .utils import (
    aligned_read, aligned_write, timestamp_pack, timestamp_unpack)


def _repr_nt(nt):
    """Nicer __repr__ for named tuples"""

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


class RawBlock(namedtuple('_RawBlock', 'block_type,contents')):
    """A raw block of the pcap-ng file structure"""

    __slots__ = []  # no instance dict!

    def __repr__(self):
        return _repr_nt(self)


class BaseBlock(object):
    def __init__(self, **kw):
        for key, val in kw.iteritems():
            if not hasattr(self, key):
                raise AttributeError(key)
            setattr(self, key, val)

    def __repr__(self):
        return _repr_nt(self)


class Packer(object):
    def __init__(self, endianness=0):
        self.endianness = endianness

    @property
    def _prefix(self):
        return {
            ENDIAN_NATIVE: '=',
            ENDIAN_LITTLE: '<',
            ENDIAN_BIG: '>',
        }[self.endianness]

    def unpack(self, fmt, data):
        return struct.unpack(self._prefix + fmt, data)

    def pack(self, fmt, *data):
        return struct.pack(self._prefix + fmt, *data)


Unpacker = Packer


class GenericBlock(BaseBlock):
    """
    A generic block packet, meaning either an unrecognised
    block or a not-yet-parsed one.
    """

    __slots__ = ['block_type', 'block_size', 'block_body']

    block_type = None
    block_size = None
    block_body = None


class SectionHeader(BaseBlock):
    # ------------------------------------------------------------
    # 4 bytes: Byte order magic
    # 2 bytes: major version
    # 2 bytes: minor version
    # 8 bytes: section length (for traversing) (-1 for "unknown")
    # ...options...
    # ------------------------------------------------------------

    block_type = BLK_SECTION_HEADER
    byte_order_magic = None  # Always 0x1a2b3c4d
    version = None  # (major, minor)
    section_length = None
    options = None  # {key: [values]}

    _options_names = {
        'opt_endofopt': 0,
        'opt_comment': 1,
        # An UTF-8 string containing the description of the hardware
        # used to create this section.
        'shb_hardware': 2,
        # An UTF-8 string containing the name of the operating system
        # used to create this section.
        'shb_os': 3,
        # An UTF-8 string containing the name of the application used
        # to create this section.
        'shb_userappl': 4,
    }

    @classmethod
    def unpack(cls, data, endianness=0):
        unpacker = Unpacker(endianness)
        (bo_magic, major, minor, section_length
         ) = unpacker.unpack('IHHq', data[:16])

        if bo_magic == 0x4d3c2b1a:
            raise ValueError("Wrong endianness!")
        if bo_magic != 0x1a2b3c4d:
            raise ValueError(
                "Invalid byte order magic! "
                "Got: 0x{0:08x}".format(bo_magic))

        obj = cls()
        obj.byte_order_magic = bo_magic
        obj.version = (major, minor)
        obj.section_length = section_length
        obj.options = Options.unpack(
            data[16:], names=cls._options_names,
            endianness=endianness)
        return obj

    def pack(self, endianness=0):
        packer = Packer(endianness)
        packed = packer.pack(
            'IHHq',
            self.byte_order_magic, self.version[0], self.version[1],
            self.section_length)
        packed_opts = self.options.pack(endianness=endianness)
        return ''.join((packed, packed_opts))


class Interface(BaseBlock):
    # ------------------------------------------------------------
    # 2 bytes: link type
    # 2 bytes: reserved
    # 4 bytes: snapshot length
    # ...options...
    # ------------------------------------------------------------

    block_type = BLK_INTERFACE
    link_type = None
    snaplen = None
    options = None

    _section = None
    _options_names = {
        'opt_endofopt': 0,
        'opt_comment': 1,
        'if_name': 2,
        'if_description': 3,
        'if_IPv4addr': 4,
        'if_IPv6addr': 5,
        'if_MACaddr': 6,
        'if_EUIaddr': 7,
        'if_speed': 8,
        'if_tsresol': 9,
        'if_tzone': 10,
        'if_filter': 11,
        'if_os': 12,
        'if_fcslen': 13,
        'if_tsoffset': 14,
    }

    @classmethod
    def unpack(cls, data, endianness=0):
        unpacker = Unpacker(endianness)
        (link_type, res, snaplen) = unpacker.unpack('HHI', data[:8])

        obj = cls()
        obj.link_type = link_type
        obj.snaplen = snaplen
        obj.options = Options.unpack(
            data[8:], names=cls._options_names,
            endianness=endianness)
        return obj

    def pack(self, endianness=0):
        packer = Packer(endianness)
        packed = packer.pack('HHI', self.link_type, 0, self.snaplen)
        packed_opts = self.options.pack(endianness=endianness)
        return ''.join((packed, packed_opts))


class Packet(BaseBlock):
    block_type = BLK_PACKET
    interface_id = None
    drops_count = None
    timestamp = None
    captured_len = None
    packet_len = None
    packet_data = None
    options = None

    _section = None
    _interface = None


class SimplePacket(BaseBlock):
    block_type = BLK_PACKET_SIMPLE
    packet_len = None
    packet_data = None

    _section = None


class EnhancedPacket(BaseBlock):
    # ------------------------------------------------------------
    # 4 bytes: interface id
    # 4 bytes: timestamp (high)
    # 4 bytes: timestamp (low)
    # 4 bytes: captured len (in the file)
    # 4 bytes: packet len (real one on the wire)
    # ...packet data... (captured-len-sized)
    # ...options...
    # ------------------------------------------------------------

    block_type = BLK_ENHANCED_PACKET
    interface_id = None
    timestamp_raw = None
    captured_len = None
    packet_len = None
    packet_data = None
    options = None

    # todo: add a timestamp property to allow manipulating in seconds

    _section = None
    _interface = None
    _options_names = {
        # A flags word containing link-layer information.
        'epb_flags': 2,
        # This option contains a hash of the packet.
        'epb_hash': 3,
        # A 64bit integer value specifying the number of packets lost
        # (by the interface and the operating system) between this
        # packet and the preceding one.
        'epb_dropcount': 4,
    }

    @classmethod
    def unpack(cls, data, endianness=0):
        stream = BytesIO(data)
        unpacker = Unpacker(endianness)

        obj = cls()
        (obj.interface_id, ts_high, ts_low, obj.captured_len, obj.packet_len
         ) = unpacker.unpack('IIIII', stream.read(20))

        obj.timestamp_raw = timestamp_unpack(ts_high, ts_low)

        obj.packet_data = aligned_read(stream, obj.packet_len)

        obj.options = Options.unpack(
            stream.read(), names=cls._options_names,
            endianness=endianness)

        return obj

    def pack(self, endianness=0):
        stream = BytesIO()
        packer = Packer(endianness)

        ts_high, ts_low = timestamp_pack(self.timestamp_raw)
        packed = packer.pack('IIIII', self.interface_id, ts_high, ts_low,
                             self.captured_len, len(self.packet_data))
        stream.write(packed)

        aligned_write(stream, self.packet_data)

        packed_opts = self.options.pack(endianness=endianness)
        aligned_write(stream, packed_opts)

        return stream.getvalue()


class NameResolution(BaseBlock):
    block_type = BLK_NAME_RESOLUTION
    records = None  # [(type, value)]
    options = None

    _section = None


class InterfaceStatistics(BaseBlock):
    block_type = BLK_INTERFACE_STATS
    interface_id = None
    timestamp = None
    options = None

    _section = None
    _interface = None


class Options(MutableMapping):
    field_names = {}  # (name: numeric_id)

    def __init__(self, values=None):
        self._data = {}  # {id: [values]}
        if values is not None:
            for key, val in values:
                self.add_value(key, val)

    @classmethod
    def unpack(cls, data, names=None, endianness=0):
        unpacker = Unpacker(endianness)
        stream = BytesIO(data)

        obj = cls()

        if names is not None:
            obj.field_names = names

        while True:
            data = stream.read(4)
            if len(data) < 4:
                break  # EOF (todo: warn?)
            o_type, o_length = unpacker.unpack('HH', data)

            if o_type == OPT_ENDOFOPT:
                break  # End of options

            o_value = aligned_read(stream, o_length)
            obj.add_value(o_type, o_value)

        return obj

    def pack(self, endianness=0):
        """
        Pack the options in a format suitable for writing inside
        a block.
        """
        packer = Packer(endianness)
        stream = BytesIO()
        for key, values in sorted(self._data.iteritems()):
            for value in values:
                stream.write(packer.pack('HH', key, len(value)))
                aligned_write(stream, value)
        stream.write(packer.pack('HH', OPT_ENDOFOPT, 0))
        return stream.getvalue()

    def __getitem__(self, name):
        if name in self.field_names:
            name = self.field_names[name]
        return self._data[name][0]

    def __setitem__(self, name, value):
        if name in self.field_names:
            name = self.field_names[name]
        self._data[name] = [value]

    def __delitem__(self, name):
        if name in self.field_names:
            name = self.field_names[name]
        del self._data[name]

    def __iter__(self):
        numeric_fields = set(self._data.iterkeys())

        for name, numeric in self.field_names.iteritems():
            if numeric in numeric_fields:
                yield name
                numeric_fields.remove(numeric)

        for fld in numeric_fields:
            # Unrecognised ones..
            yield fld

    def __len__(self):
        return len(self._data)

    def add_value(self, name, value):
        if name in self.field_names:
            name = self.field_names[name]
        if name not in self._data:
            self._data[name] = []
        self._data[name].append(value)

    def get_values(self, name):
        if name in self.field_names:
            name = self.field_names[name]
        return list(self._data[name])  # copy!
