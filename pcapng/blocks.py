import io

from pcapng.structs import (
    struct_decode, RawBytes, IntField, OptionsField, PacketDataField,
    ListField, NameResolutionRecordField, SimplePacketDataField)


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


@register_block
class EnhancedPacket(SectionMemberBlock):
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

    @property
    def interface(self):
        # We need to get the correct interface from the section
        # by looking up the interface_id
        return self.section.interfaces[self.interface_id]


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
class Packet(SectionMemberBlock):
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

    @property
    def interface(self):
        # We need to get the correct interface from the section
        # by looking up the interface_id
        pass


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


class UnknownBlock(Block):
    def __init__(self, block_type, data):
        self.block_type = block_type
        self.data = data

    def __repr__(self):
        return ('UnknownBlock(0x{0:08X}, {1!r})'
                .format(self.block_type, self.data))
