from pcapng.objects import SectionHeader


EXAMPLE_SECTION_LE = (
    "\xa0\xd0\xd0\xa0"  # Magic number
    "\x20\x00\x00\x00"  # Block size (32 bytes)
    "\x4d\x3c\x2b\x1a"  # Magic number
    "\x01\x00\x00\x00"  # Version
    "\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
    "\x00\x00\x00\x00"  # Empty options
    "\x20\x00\x00\x00"  # Block size (32 bytes)
)
EXAMPLE_SECTION_BE = (
    "\xa0\xd0\xd0\xa0"  # Magic number
    "\x00\x00\x00\x20"  # Block size (32 bytes)
    "\x1a\x2b\x3c\x4d"  # Magic number
    "\x00\x01\x00\x00"  # Version
    "\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
    "\x00\x00\x00\x00"  # Empty options
    "\x00\x00\x00\x20"  # Block size (32 bytes)
)


def test_read_sample_section_le():
    se = SectionHeader.unpack(EXAMPLE_SECTION_LE[8:-4], endianness=1)

    assert se.block_type == 0x0a0d0d0a
    assert se.byte_order_magic == 0x1a2b3c4d
    assert se.version == (1, 0)
    assert se.section_length == -1
    assert len(se.options) == 0

    assert se.pack(endianness=1) == EXAMPLE_SECTION_LE[8:-4]
    assert se.pack(endianness=2) == EXAMPLE_SECTION_BE[8:-4]
