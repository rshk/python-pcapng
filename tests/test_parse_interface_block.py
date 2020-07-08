import io

from pcapng.blocks import InterfaceDescription, SectionHeader
from pcapng.scanner import FileScanner


def test_read_block_interface_bigendian():
    scanner = FileScanner(
        io.BytesIO(
            # ---------- Section header
            b"\x0a\x0d\x0d\x0a"  # Magic number
            b"\x00\x00\x00\x20"  # Block size (32 bytes)
            b"\x1a\x2b\x3c\x4d"  # Magic number
            b"\x00\x01\x00\x00"  # Version
            b"\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
            b"\x00\x00\x00\x00"  # Empty options
            b"\x00\x00\x00\x20"  # Block size (32 bytes)
            # ---------- Interface description
            b"\x00\x00\x00\x01"  # block magic
            b"\x00\x00\x00\x40"  # block syze (64 bytes)
            b"\x00\x01"  # link type
            b"\x00\x00"  # reserved block
            b"\x00\x00\xff\xff"  # size limit
            b"\x00\x02\x00\x04"
            b"eth0"  # if_name
            b"\x00\x09\x00\x01"
            b"\x06\x00\x00\x00"  # if_tsresol (+padding)
            b"\x00\x0c\x00\x13"
            b"Linux 3.2.0-4-amd64\x00"  # if_os
            b"\x00\x00\x00\x00"  # end of options
            b"\x00\x00\x00\x40"  # block syze (64 bytes)
        )
    )

    blocks = list(scanner)
    assert len(blocks) == 2

    assert isinstance(blocks[0], SectionHeader)
    assert blocks[0].endianness == ">"
    assert blocks[0].interfaces == {0: blocks[1]}

    assert isinstance(blocks[1], InterfaceDescription)
    assert blocks[1].link_type == 0x01
    assert blocks[1].link_type_description == "D/I/X and 802.3 Ethernet"
    assert blocks[1].snaplen == 0xFFFF
    assert blocks[1].options["if_name"] == "eth0"
    assert blocks[1].options["if_tsresol"] == b"\x06"
    assert blocks[1].timestamp_resolution == 1e-6
    assert blocks[1].options["if_os"] == "Linux 3.2.0-4-amd64"
    assert blocks[1].reserved == 0

    assert repr(blocks[1]) == (
        "<InterfaceDescription link_type=1 reserved={reserved} "
        "snaplen=65535 options={options}>".format(
            options=repr(blocks[1].options), reserved=repr(blocks[1].reserved)
        )
    )


def test_read_block_interface_nondefault_tsresol():
    scanner = FileScanner(
        io.BytesIO(
            # ---------- Section header
            b"\x0a\x0d\x0d\x0a"  # Magic number
            b"\x00\x00\x00\x20"  # Block size (32 bytes)
            b"\x1a\x2b\x3c\x4d"  # Magic number
            b"\x00\x01\x00\x00"  # Version
            b"\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
            b"\x00\x00\x00\x00"  # Empty options
            b"\x00\x00\x00\x20"  # Block size (32 bytes)
            # ---------- Interface description
            b"\x00\x00\x00\x01"  # block magic
            b"\x00\x00\x00\x20"  # block syze (64 bytes)
            b"\x00\x01"  # link type
            b"\x00\x00"  # reserved block
            b"\x00\x00\xff\xff"  # size limit
            b"\x00\x09\x00\x01"
            b"\x0c\x00\x00\x00"  # if_tsresol (+padding)
            b"\x00\x00\x00\x00"  # end of options
            b"\x00\x00\x00\x20"  # block syze (64 bytes)
        )
    )

    blocks = list(scanner)
    assert len(blocks) == 2

    assert isinstance(blocks[1], InterfaceDescription)
    assert blocks[1].options["if_tsresol"] == b"\x0c"
    assert "if_tsresol" in blocks[1].options
    assert blocks[1].timestamp_resolution == 1e-12


def test_read_block_interface_unknown_link_type():
    scanner = FileScanner(
        io.BytesIO(
            # ---------- Section header
            b"\x0a\x0d\x0d\x0a"  # Magic number
            b"\x00\x00\x00\x20"  # Block size (32 bytes)
            b"\x1a\x2b\x3c\x4d"  # Magic number
            b"\x00\x01\x00\x00"  # Version
            b"\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
            b"\x00\x00\x00\x00"  # Empty options
            b"\x00\x00\x00\x20"  # Block size (32 bytes)
            # ---------- Interface description
            b"\x00\x00\x00\x01"  # block magic
            b"\x00\x00\x00\x18"  # block syze
            b"\xff\x01"  # link type (unknown)
            b"\x00\x00"  # reserved block
            b"\x00\x00\xff\xff"  # size limit
            b"\x00\x00\x00\x00"  # end of options
            b"\x00\x00\x00\x18"  # block syze (64 bytes)
        )
    )

    blocks = list(scanner)
    assert len(blocks) == 2

    assert isinstance(blocks[1], InterfaceDescription)
    assert blocks[1].link_type == 0xFF01
    assert blocks[1].link_type_description == "Unknown link type: 0xff01"
