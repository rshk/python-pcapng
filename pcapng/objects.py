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
from .utils import aligned_read, aligned_write


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
    block_type = BLK_SECTION_HEADER
    byte_order_magic = None  # Always 0x1a2b3c4d
    version = None  # (major, minor)
    section_length = None
    options = None  # {key: [values]}

    _options_names = {}

    # 4 bytes: byte_order_magic
    # 2 bytes: major version
    # 2 bytes: minor version
    # 8 bytes: section length (for traversing) (-1 for "unknown")
    # ...options for the remaining length...

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
    block_type = BLK_INTERFACE
    link_type = None
    snaplen = None
    options = None

    _section = None

    @classmethod
    def unpack(cls, data, endianness=0):
        unpacker = Unpacker(endianness)


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
    block_type = BLK_ENHANCED_PACKET
    interface_id = None
    timestamp = None
    captured_len = None
    packet_len = None
    packet_data = None
    options = None

    _section = None
    _interface = None


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
        for key, values in self._data.iteritems():
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
