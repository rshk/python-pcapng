import io

from pcapng.blocks import SectionHeader, InterfaceDescription, EnhancedPacket
from pcapng.scanner import FileScanner


def test_read_block_enhanced_packet_bigendian():
    scanner = FileScanner(io.BytesIO(
        # ---------- Section header
        "\x0a\x0d\x0d\x0a"  # Magic number
        "\x00\x00\x00\x20"  # Block size (32 bytes)
        "\x1a\x2b\x3c\x4d"  # Magic number
        "\x00\x01\x00\x00"  # Version
        "\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
        "\x00\x00\x00\x00"  # Empty options
        "\x00\x00\x00\x20"  # Block size (32 bytes)

        # ---------- Interface description
        '\x00\x00\x00\x01'  # block magic
        '\x00\x00\x00\x40'  # block syze (64 bytes)
        '\x00\x01'  # link type
        '\x00\x00'  # reserved block
        '\x00\x00\xff\xff'  # size limit
        '\x00\x02\x00\x04''eth0'  # if_name
        '\x00\x09\x00\x01''\x06\x00\x00\x00'  # if_tsresol (+padding)
        '\x00\x0c\x00\x13''Linux 3.2.0-4-amd64\x00'  # if_os
        '\x00\x00\x00\x00'  # end of options
        '\x00\x00\x00\x40'  # block syze (64 bytes)

        # ---------- Enhanced packet
        '\x00\x00\x00\x06'  # block magic
        '\x00\x00\x00\x78'  # block syze (120 bytes)

        '\x00\x00\x00\x00'  # interface id (first one, eth0)
        '\x00\x04\xf8\x1e''\x3c\x3e\xd5\xa9'  # timestamp (microseconds)

        '\x00\x00\x00\x51'  # Captured length
        '\x00\x00\x00\x51'  # Original length

        # Packet data (81 bytes)
        '\x00\x02\x157\xa2D\x00\xae\xf3R\xaa\xd1\x08\x00'  # Ethernet
        'E\x00\x00C\x00\x01\x00\x00@\x06x<\xc0\xa8\x05\x15B#\xfa\x97'  # IP
        '\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 '  # TCP
        '\x00\xbb9\x00\x00'  # TCP(cont)
        'GET /index.html HTTP/1.0 \n\n'  # HTTP
        '\x00\x00\x00'  # Padding

        # todo: add options?
        '\x00\x00\x00\x00'  # Empty options

        '\x00\x00\x00\x78'  # block syze (120 bytes)
        ))

    blocks = list(scanner)
    assert len(blocks) == 3

    assert isinstance(blocks[0], SectionHeader)
    assert blocks[0].endianness == '>'
    assert blocks[0].interfaces == {0: blocks[1]}

    assert isinstance(blocks[1], InterfaceDescription)
    assert blocks[1].section == blocks[0]
    assert blocks[1].link_type == 0x01
    assert blocks[1].snaplen == 0xffff
    assert blocks[1].options['if_name'] == 'eth0'
    assert blocks[1].options['if_tsresol'] == '\x06'

    assert isinstance(blocks[2], EnhancedPacket)
    assert blocks[2].section == blocks[0]
    assert blocks[2].interface_id == 0
    assert blocks[2].interface == blocks[1]

    assert blocks[2].timestamp_high == 0x0004f81e
    assert blocks[2].timestamp_low == 0x3c3ed5a9
    assert blocks[2].timestamp_resolution == -6
    assert blocks[2].timestamp == 1398708650.3008409

    assert blocks[2].captured_len == 0x51
    assert blocks[2].packet_len == 0x51
    assert blocks[2].packet_data == (
        '\x00\x02\x157\xa2D\x00\xae\xf3R\xaa\xd1\x08\x00'  # Ethernet
        'E\x00\x00C\x00\x01\x00\x00@\x06x<\xc0\xa8\x05\x15B#\xfa\x97'  # IP
        '\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 '  # TCP
        '\x00\xbb9\x00\x00'  # TCP(cont)
        'GET /index.html HTTP/1.0 \n\n')  # HTTP
    assert len(blocks[2].options) == 0
