from pcapng.objects import EnhancedPacket


EXAMPLE_EPACKET_LE = (
    '\x06\x00\x00\x00'  # block magic
    '\x78\x00\x00\x00'  # block syze (120 bytes)

    '\x00\x00\x00\x00'  # interface id
    '\x1e\xf8\x04\x00''\xa9\xd5\x3e\x3c'  # timestamp (microseconds)

    '\x51\x00\x00\x00'  # Captured length
    '\x51\x00\x00\x00'  # Original length

    # Packet data (81 bytes)
    '\x00\x02\x157\xa2D\x00\xae\xf3R\xaa\xd1\x08\x00'  # Ethernet
    'E\x00\x00C\x00\x01\x00\x00@\x06x<\xc0\xa8\x05\x15B#\xfa\x97'  # IP
    '\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 '  # TCP
    '\x00\xbb9\x00\x00'  # TCP(cont)
    'GET /index.html HTTP/1.0 \n\n'  # HTTP
    '\x00\x00\x00'  # Padding

    '\x00\x00\x00\x00'  # Empty options

    '\x78\x00\x00\x00'  # block syze (120 bytes)
)
EXAMPLE_EPACKET_BE = (
    '\x00\x00\x00\x06'  # block magic
    '\x00\x00\x00\x78'  # block syze (120 bytes)

    '\x00\x00\x00\x00'  # interface id
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

    '\x00\x00\x00\x00'  # Empty options

    '\x00\x00\x00\x78'  # block syze (120 bytes)
)


def test_read_sample_interface_le():
    se = EnhancedPacket.unpack(EXAMPLE_EPACKET_LE[8:-4], endianness=1)

    assert se.interface_id == 0
    assert se.timestamp_raw == 1398708650300841
    assert se.captured_len == 0x51
    assert se.packet_len == 0x51
    assert len(se.packet_data) == 0x51
    assert se.packet_data.endswith('GET /index.html HTTP/1.0 \n\n')
    assert len(se.options) == 0

    assert se.pack(endianness=1) == EXAMPLE_EPACKET_LE[8:-4]
    assert se.pack(endianness=2) == EXAMPLE_EPACKET_BE[8:-4]


def test_read_sample_interface_be():
    se = EnhancedPacket.unpack(EXAMPLE_EPACKET_BE[8:-4], endianness=2)

    assert se.interface_id == 0
    assert se.timestamp_raw == 1398708650300841
    assert se.captured_len == 0x51
    assert se.packet_len == 0x51
    assert len(se.packet_data) == 0x51
    assert se.packet_data.endswith('GET /index.html HTTP/1.0 \n\n')
    assert len(se.options) == 0

    assert se.pack(endianness=1) == EXAMPLE_EPACKET_LE[8:-4]
    assert se.pack(endianness=2) == EXAMPLE_EPACKET_BE[8:-4]
