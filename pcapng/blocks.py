import io
import struct

from pcapng.structs import (
    struct_decode, RawBytes, IntField, OptionsField, PacketDataField,
    ListField, NameResolutionRecordField, SimplePacketDataField)
from pcapng.constants import link_types


KNOWN_BLOCKS = {}


class Block(object):
    schema = []

    def __init__(self, raw):
        self._raw = raw
        self._decoded = None

    @classmethod
    def from_context(cls, raw, ctx):
        return cls(raw)

    def _decode(self):
        return struct_decode(self.schema, io.BytesIO(self._raw),
                             endianness=self.section.endianness)

    def __getattr__(self, name):
        if self._decoded is None:
            self._decoded = self._decode()
        try:
            return self._decoded[name]
        except KeyError:
            raise AttributeError(name)

    def __repr__(self):
        args = []
        for item in self.schema:
            name = item[0]
            args.append('{0}={1!r}'.format(name, getattr(self, name)))
        return '{0}({1})'.format(self.__class__.__name__,
                                 ', '.join(args))


class SectionMemberBlock(Block):
    def __init__(self, raw, section):
        super(SectionMemberBlock, self).__init__(raw)
        self.section = section

    @classmethod
    def from_context(cls, raw, ctx):
        return cls(raw, section=ctx.current_section)


def register_block(block):
    KNOWN_BLOCKS[block.magic_number] = block
    return block


@register_block
class SectionHeader(Block):
    magic_number = 0x0a0d0d0a
    schema = []

    def __init__(self, endianness, version, length, options):
        self.endianness = endianness
        self.version = version
        self.length = length
        self.options = options
        self.interfaces = []
        self.interface_stats = {}


@register_block
class InterfaceDescription(SectionMemberBlock):
    magic_number = 0x00000001
    schema = [
        ('link_type', IntField(16, False)),  # todo: enc/decode
        ('reserved', RawBytes(2)),
        ('snaplen', IntField(32, False)),
        ('options', OptionsField([
            (2, 'if_name'),
            (3, 'if_description'),
            (4, 'if_IPv4addr'),
            (5, 'if_IPv6addr'),
            (6, 'if_MACaddr'),
            (7, 'if_EUIaddr'),
            (8, 'if_speed'),
            (9, 'if_tsresol'),
            (10, 'if_tzone'),
            (11, 'if_filter'),
            (12, 'if_os'),
            (13, 'if_fcslen'),
            (14, 'if_tsoffset'),
        ]))]

    @property  # todo: cache this property
    def timestamp_resolution(self):
        # ts_resol is a 8-bit integer representing the power of ten
        # of the timestamp multiplier. If not specified, -6 is assumed
        if 'ts_resol' in self.options:
            resol = self.options['ts_resol']
            return struct.unpack('b', resol)[0]
        return -6

    @property
    def statistics(self):
        # todo: we need to make the interface aware of its own id
        raise NotImplementedError

    @property
    def link_type_description(self):
        try:
            return link_types.LINKTYPE_DESCRIPTIONS[self.link_type]
        except KeyError:
            return 'Unknown link type: 0x{0:04X}'.format(self.link_type)


class BlockWithTimestampMixin(object):
    @property
    def timestamp(self):
        # First, get the accuracy from the ts_resol option
        return (((self.timestamp_high << 32) + self.timestamp_low)
                * (10 ** self.timestamp_resolution))

    @property
    def timestamp_resolution(self):
        return self.interface.timestamp_resolution


class BlockWithInterfaceMixin(object):
    @property
    def interface(self):
        # We need to get the correct interface from the section
        # by looking up the interface_id
        return self.section.interfaces[self.interface_id]


class BasePacketBlock(
        SectionMemberBlock,
        BlockWithInterfaceMixin,
        BlockWithTimestampMixin):
    pass


@register_block
class EnhancedPacket(BasePacketBlock):
    magic_number = 0x00000006
    schema = [
        ('interface_id', IntField(32, False)),
        ('timestamp_high', IntField(32, False)),
        ('timestamp_low', IntField(32, False)),
        ('packet_payload_info', PacketDataField()),
        ('options', OptionsField([
            (2, 'epb_flags'),
            (3, 'epb_hash'),
            (4, 'epb_dropcount'),
        ]))
    ]

    @property
    def captured_len(self):
        return self.packet_payload_info[0]

    @property
    def packet_len(self):
        return self.packet_payload_info[1]

    @property
    def packet_data(self):
        return self.packet_payload_info[2]

    # todo: add some property returning a datetime() with timezone..


@register_block
class SimplePacket(SectionMemberBlock):
    magic_number = 0x00000003
    schema = [
        ('packet_simple_payload_info', SimplePacketDataField()),
    ]

    @property
    def packet_len(self):
        return self.packet_simple_payload_info[1]

    @property
    def packet_data(self):
        return self.packet_simple_payload_info[2]


@register_block
class Packet(BasePacketBlock):
    magic_number = 0x00000002
    schema = [
        ('interface_id', IntField(16, False)),
        ('drops_count', IntField(16, False)),
        ('timestamp_high', IntField(32, False)),
        ('timestamp_low', IntField(32, False)),
        ('packet_payload_info', PacketDataField()),
        ('options', OptionsField([
            (2, 'epb_flags', IntField(32, False)),  # A flag!
            (3, 'epb_hash'),  # Variable size!
        ]))
    ]

    @property
    def captured_len(self):
        return self.packet_payload_info[0]

    @property
    def packet_len(self):
        return self.packet_payload_info[1]

    @property
    def packet_data(self):
        return self.packet_payload_info[2]


@register_block
class NameResolution(SectionMemberBlock):
    magic_number = 0x00000004
    schema = [
        ('records', ListField(NameResolutionRecordField())),
        ('options', OptionsField([
            (2, 'ns_dnsname'),
            (3, 'ns_dnsIP4addr'),
            (4, 'ns_dnsIP6addr'),
        ])),
    ]


@register_block
class InterfaceStatistics(SectionMemberBlock, BlockWithTimestampMixin,
                          BlockWithInterfaceMixin):
    magic_number = 0x00000005
    schema = [
        ('interface_id', IntField(32, False)),
        ('timestamp_high', IntField(32, False)),
        ('timestamp_low', IntField(32, False)),
        ('options', OptionsField([
            (2, 'isb_starttime'),
            (3, 'isb_endtime'),
            (4, 'isb_ifrecv'),
            (5, 'isb_ifdrop'),
            (6, 'isb_filteraccept'),
            (7, 'isb_osdrop'),
            (8, 'isb_usrdeliv'),
        ])),
    ]


class UnknownBlock(Block):
    def __init__(self, block_type, data):
        self.block_type = block_type
        self.data = data

    def __repr__(self):
        return ('UnknownBlock(0x{0:08X}, {1!r})'
                .format(self.block_type, self.data))
