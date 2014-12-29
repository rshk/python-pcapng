import io

from pcapng.blocks import SectionHeader, InterfaceDescription
from pcapng.scanner import FileScanner


def test_read_block_interface_bigendian():
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
    ))

    blocks = list(scanner)
    assert len(blocks) == 2

    assert isinstance(blocks[0], SectionHeader)
    assert blocks[0].endianness == '>'
    assert blocks[0].interfaces == {0: blocks[1]}

    assert isinstance(blocks[1], InterfaceDescription)
    assert blocks[1].link_type == 0x01
    assert blocks[1].link_type_description == 'D/I/X and 802.3 Ethernet'
    assert blocks[1].snaplen == 0xffff
    assert blocks[1].options['if_name'] == 'eth0'
    assert blocks[1].options['if_tsresol'] == '\x06'
    assert blocks[1].timestamp_resolution == 1e-6
    assert blocks[1].options['if_os'] == 'Linux 3.2.0-4-amd64'

    assert repr(blocks[1]) == (
        "<InterfaceDescription link_type=1 reserved='\\x00\\x00' "
        "snaplen=65535 options={options}>"
        .format(options=repr(blocks[1].options)))


def test_read_block_interface_nondefault_tsresol():
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
        '\x00\x09\x00\x01''\x0c\x00\x00\x00'  # if_tsresol (+padding)
        '\x00\x0c\x00\x13''Linux 3.2.0-4-amd64\x00'  # if_os
        '\x00\x00\x00\x00'  # end of options
        '\x00\x00\x00\x40'  # block syze (64 bytes)
    ))

    blocks = list(scanner)
    assert len(blocks) == 2

    assert isinstance(blocks[1], InterfaceDescription)
    assert blocks[1].options['if_tsresol'] == '\x0c'
    assert 'if_tsresol' in blocks[1].options
    assert blocks[1].timestamp_resolution == 1e-12
