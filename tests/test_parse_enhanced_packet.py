import io
import struct

import pytest

from pcapng.blocks import EnhancedPacket, InterfaceDescription, SectionHeader
from pcapng.scanner import FileScanner
from pcapng.utils import pack_timestamp_resolution


def test_read_block_enhanced_packet_bigendian():
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
            # ---------- Enhanced packet
            b"\x00\x00\x00\x06"  # block magic
            b"\x00\x00\x00\x78"  # block syze (120 bytes)
            b"\x00\x00\x00\x00"  # interface id (first one, eth0)
            b"\x00\x04\xf8\x1e"
            b"\x3c\x3e\xd5\xa9"  # timestamp (microseconds)
            b"\x00\x00\x00\x51"  # Captured length
            b"\x00\x00\x00\x51"  # Original length
            # Packet data (81 bytes)
            b"\x00\x02\x157\xa2D\x00\xae\xf3R\xaa\xd1\x08\x00"  # Ethernet
            b"E\x00\x00C\x00\x01\x00\x00@\x06x<\xc0\xa8\x05\x15B#\xfa\x97"  # IP
            b"\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 "  # TCP
            b"\x00\xbb9\x00\x00"  # TCP(cont)
            b"GET /index.html HTTP/1.0 \n\n"  # HTTP
            b"\x00\x00\x00"  # Padding
            # todo: add options?
            b"\x00\x00\x00\x00"  # Empty options
            b"\x00\x00\x00\x78"  # block syze (120 bytes)
        )
    )

    blocks = list(scanner)
    assert len(blocks) == 3

    assert isinstance(blocks[0], SectionHeader)
    assert blocks[0].endianness == ">"
    assert blocks[0].interfaces == {0: blocks[1]}

    assert isinstance(blocks[1], InterfaceDescription)
    assert blocks[1].section == blocks[0]
    assert blocks[1].link_type == 0x01
    assert blocks[1].snaplen == 0xFFFF
    assert blocks[1].options["if_name"] == "eth0"
    assert blocks[1].options["if_tsresol"] == b"\x06"

    assert isinstance(blocks[2], EnhancedPacket)
    assert blocks[2].section == blocks[0]
    assert blocks[2].interface_id == 0
    assert blocks[2].interface == blocks[1]

    assert blocks[2].timestamp_high == 0x0004F81E
    assert blocks[2].timestamp_low == 0x3C3ED5A9
    assert blocks[2].timestamp_resolution == 1e-6
    assert blocks[2].timestamp == 1398708650.3008409

    assert blocks[2].captured_len == 0x51
    assert blocks[2].packet_len == 0x51
    assert blocks[2].packet_data == (
        b"\x00\x02\x157\xa2D\x00\xae\xf3R\xaa\xd1\x08\x00"  # Ethernet
        b"E\x00\x00C\x00\x01\x00\x00@\x06x<\xc0\xa8\x05\x15B#\xfa\x97"  # IP
        b"\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 "  # TCP
        b"\x00\xbb9\x00\x00"  # TCP(cont)
        b"GET /index.html HTTP/1.0 \n\n"
    )  # HTTP
    assert len(blocks[2].options) == 0


def _generate_file_with_tsresol(base, exponent):
    tsresol = pack_timestamp_resolution(base, exponent)
    base_timestamp = 1420070400.0  # 2015-01-01 00:00 UTC
    timestamp = base_timestamp / (base**exponent)

    stream = io.BytesIO()

    # ---------- Section header
    stream.write(b"\x0a\x0d\x0d\x0a")  # Magic number
    stream.write(b"\x00\x00\x00\x20")  # Block size (32 bytes)
    stream.write(b"\x1a\x2b\x3c\x4d")  # Magic number
    stream.write(b"\x00\x01\x00\x00")  # Version
    stream.write(b"\xff\xff\xff\xff\xff\xff\xff\xff")  # Undefined length
    stream.write(b"\x00\x00\x00\x00")  # Empty options
    stream.write(b"\x00\x00\x00\x20")  # Block size (32 bytes)

    # ---------- Interface description
    stream.write(b"\x00\x00\x00\x01")  # block magic
    stream.write(b"\x00\x00\x00\x20")  # block syze
    stream.write(b"\x00\x01")  # link type
    stream.write(b"\x00\x00")  # reserved block
    stream.write(b"\x00\x00\xff\xff")  # size limit
    stream.write(b"\x00\x09\x00\x01")
    stream.write(tsresol)
    stream.write(b"\x00\x00\x00")  # if_tsresol (+padding)
    stream.write(b"\x00\x00\x00\x00")  # end of options
    stream.write(b"\x00\x00\x00\x20")  # block syze

    # ---------- Enhanced packet
    stream.write(b"\x00\x00\x00\x06")  # block magic
    stream.write(b"\x00\x00\x00\x24")  # block syze
    stream.write(b"\x00\x00\x00\x00")  # interface id (first one, eth0)
    stream.write(struct.pack(">Q", int(timestamp)))  # timestamp
    stream.write(b"\x00\x00\x00\x00")  # Captured length
    stream.write(b"\x00\x00\x00\x00")  # Original length
    # no packet data
    stream.write(b"\x00\x00\x00\x00")  # Empty options
    stream.write(b"\x00\x00\x00\x24")  # block syze

    return stream.getvalue()


@pytest.mark.parametrize(
    "tsr_base,tsr_exp",
    [
        (10, -6),
        (10, 0),
        (10, -3),
        (10, -9),  # Bigger than this won't even fit..
        (2, 0),
        (2, -5),
        (2, -10),
        (2, -20),
    ],
)
def test_read_block_enhanced_packet_tsresol_bigendian(tsr_base, tsr_exp):
    data = _generate_file_with_tsresol(tsr_base, tsr_exp)
    scanner = FileScanner(io.BytesIO(data))

    blocks = list(scanner)
    assert len(blocks) == 3

    assert isinstance(blocks[0], SectionHeader)
    assert blocks[0].endianness == ">"
    assert blocks[0].interfaces == {0: blocks[1]}

    assert isinstance(blocks[1], InterfaceDescription)
    assert len(blocks[1].options) == 1  # Just if_tsresol
    assert blocks[1].options["if_tsresol"] == pack_timestamp_resolution(
        tsr_base, tsr_exp
    )

    assert isinstance(blocks[2], EnhancedPacket)
    assert blocks[2].section == blocks[0]
    assert blocks[2].interface_id == 0
    assert blocks[2].interface == blocks[1]

    resol = tsr_base**tsr_exp
    assert blocks[2].timestamp_resolution == resol
    assert blocks[2].timestamp == 1420070400.0
