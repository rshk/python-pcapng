from pcapng.objects import Interface


EXAMPLE_INTERFACE_LE = (
    '\x01\x00\x00\x00'  # block magic
    '\x40\x00\x00\x00'  # block syze (64 bytes)
    '\x01\x00'  # link type
    '\x00\x00'  # reserved block
    '\xff\xff\x00\x00'  # size limit
    '\x02\x00\x04\x00''eth0'  # if_name
    '\x09\x00\x01\x00''\x06\x00\x00\x00'  # if_tsresol (+padding)
    '\x0c\x00\x13\x00''Linux 3.2.0-4-amd64\x00'  # if_os
    '\x00\x00\x00\x00'  # end of options
    '\x40\x00\x00\x00'  # block syze (64 bytes)
)
EXAMPLE_INTERFACE_BE = (
    '\x00\x00\x00\x01'  # block magic
    '\x00\x00\x00\x40'  # block syze (64 bytes)
    '\x00\x01'  # link type
    '\x00\x00'  # reserved block
    '\x00\x00\xff\xff'  # size limit
    '\x00\x02\x00\x04''eth0'  # if_name
    '\x00\x09\x00\x01''\x06\x00\x00\x00'  # if_tsresol (+padding)
    '\x00\x0c\x00\x13''Linux 3.2.0-4-amd64\x00'  # if_os
    '\x00\x00\x00\x00'  # end of options
    '\x00\x40\x00\x00'  # block syze (64 bytes)
)


def test_read_sample_interface_le():
    se = Interface.unpack(EXAMPLE_INTERFACE_LE[8:-4], endianness=1)

    assert se.block_type == 0x00000001
    assert se.link_type == 1
    assert se.snaplen == 65535
    assert len(se.options) == 3
    assert se.options['if_name'] == 'eth0'
    assert se.options['if_os'] == 'Linux 3.2.0-4-amd64'
    assert se.options['if_tsresol'] == '\x06'

    assert se.pack(endianness=1) == EXAMPLE_INTERFACE_LE[8:-4]
    assert se.pack(endianness=2) == EXAMPLE_INTERFACE_BE[8:-4]


def test_read_sample_interface_be():
    se = Interface.unpack(EXAMPLE_INTERFACE_BE[8:-4], endianness=2)

    assert se.block_type == 0x00000001
    assert se.link_type == 1
    assert se.snaplen == 65535
    assert len(se.options) == 3
    assert se.options['if_name'] == 'eth0'
    assert se.options['if_os'] == 'Linux 3.2.0-4-amd64'
    assert se.options['if_tsresol'] == '\x06'

    assert se.pack(endianness=1) == EXAMPLE_INTERFACE_LE[8:-4]
    assert se.pack(endianness=2) == EXAMPLE_INTERFACE_BE[8:-4]
