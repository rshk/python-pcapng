import io

from pcapng.blocks import (
    SectionHeader, InterfaceDescription, InterfaceStatistics)
from pcapng.scanner import FileScanner


def test_read_block_interface_stats_bigendian():
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

        '\x00\x00\x00\x00'  # End of options
        '\x00\x00\x00\x40'  # block syze (64 bytes)

        # ---------- Interface statistics
        '\x00\x00\x00\x05'  # Magic number
        '\x00\x00\x00\x80'  # block size (128 bytes)
        '\x00\x00\x00\x00'  # interface id
        '\x00\x05\x0b\x5f\x61\xf8\x14\x40'  # Timestamp

        '\x00\x01\x00\x0a''A comment\x00\x00\x00'
        '\x00\x02\x00\x08''\x00\x05\x0b\x5f\x64\xa6\xb9\x80'  # isb_starttime
        '\x00\x03\x00\x08''\x00\x05\x0b\x5f\x6b\x44\x73\x40'  # isb_endtime
        '\x00\x04\x00\x08''\x00\x00\x00\x00\x00\x01\x23\x45'  # isb_ifrecv
        '\x00\x05\x00\x08''\x00\x00\x00\x00\x00\x00\x00\x20'  # isb_drop
        '\x00\x06\x00\x08''\x00\x00\x00\x00\x00\x00\x0a\xbc'  # isb_filteraccept  # noqa
        '\x00\x07\x00\x08''\x00\x00\x00\x00\x00\x00\x00\x33'  # isb_osdrop
        '\x00\x08\x00\x08''\x00\x00\x00\x00\x00\x0a\xbc\xde'  # isb_usrdeliv

        '\x00\x00\x00\x00'  # End of options
        '\x00\x00\x00\x80'  # block size (16 bytes)
    ))

    blocks = list(scanner)
    assert len(blocks) == 3

    assert isinstance(blocks[0], SectionHeader)
    assert blocks[0].endianness == '>'
    assert blocks[0].interfaces == {0: blocks[1]}

    assert isinstance(blocks[1], InterfaceDescription)

    assert isinstance(blocks[2], InterfaceStatistics)
    assert blocks[2].timestamp == 0x050b5f61f81440 / 1e6
    assert blocks[2].options['isb_starttime'] == 0x050b5f64a6b980  # no resol!
    assert blocks[2].options['isb_endtime'] == 0x050b5f6b447340  # no resol!
    assert blocks[2].options['isb_ifrecv'] == 0x12345
    assert blocks[2].options['isb_ifdrop'] == 0x20
    assert blocks[2].options['isb_filteraccept'] == 0xabc
    assert blocks[2].options['isb_osdrop'] == 0x33
    assert blocks[2].options['isb_usrdeliv'] == 0xabcde
