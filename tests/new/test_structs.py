"""
Test unpacking structs
"""

import io
import struct

import pytest

from pcapng.structs import (
    read_int, read_section_header, read_block_data, read_bytes,
    read_bytes_padded, RawBytes, IntField, struct_decode, read_options,
    Options, OptionsField, PacketDataField, SimplePacketDataField, ListField,
    NameResolutionRecordField)
from pcapng.exceptions import (
    StreamEmpty, TruncatedFile, BadMagic, CorruptedFile)


def test_read_int():
    # 16bit, signed, positive
    assert read_int(io.BytesIO('\x12\x34'), 16, True, '>') == 0x1234
    assert read_int(io.BytesIO('\x12\x34'), 16, True, '<') == 0x3412

    assert read_int(io.BytesIO('\x12\x34extra'), 16, True, '>') == 0x1234
    assert read_int(io.BytesIO('\x12\x34extra'), 16, True, '<') == 0x3412

    # 16bit, signed, negative
    assert read_int(io.BytesIO('\xed\xcc'), 16, True, '>') == -0x1234
    assert read_int(io.BytesIO('\xcc\xed'), 16, True, '<') == -0x1234

    assert read_int(io.BytesIO('\xed\xccextra'), 16, True, '>') == -0x1234
    assert read_int(io.BytesIO('\xcc\xedextra'), 16, True, '<') == -0x1234

    # 16bit, unsigned
    assert read_int(io.BytesIO('\x12\x34'), 16, False, '>') == 0x1234
    assert read_int(io.BytesIO('\x12\x34'), 16, False, '<') == 0x3412

    assert read_int(io.BytesIO('\x12\x34extra'), 16, False, '>') == 0x1234
    assert read_int(io.BytesIO('\x12\x34extra'), 16, False, '<') == 0x3412

    # ..do we really need to test other sizes?
    assert read_int(io.BytesIO('\x12\x34\x56\x78'), 32, False, '>') == 0x12345678  # noqa
    assert read_int(io.BytesIO('\x12\x34\x56\x78'), 32, False, '<') == 0x78563412  # noqa
    assert read_int(io.BytesIO('\x12\x34\x56\x78'), 32, True, '>') == 0x12345678  # noqa
    assert read_int(io.BytesIO('\x12\x34\x56\x78'), 32, True, '<') == 0x78563412  # noqa


def test_read_int_empty_stream():
    with pytest.raises(StreamEmpty):
        read_int(io.BytesIO(''), 32)


def test_read_int_truncated_stream():
    with pytest.raises(TruncatedFile):
        read_int(io.BytesIO('AB'), 32)


def test_read_section_header_big_endian():
    data = io.BytesIO(
        '\x0a\x0d\x0d\x0a'  # magic number
        '\x00\x00\x00\x1c'  # block length (28 bytes)
        '\x1a\x2b\x3c\x4d'  # byte order magic [it's big endian!]
        '\x00\x01\x00\x00'  # version 1.0
        '\xff\xff\xff\xff\xff\xff\xff\xff'  # section length unknown
        ''  # no options here!
        '\x00\x00\x00\x1c')  # block length, again

    block = read_section_header(data)
    assert block['endianness'] == '>'
    assert block['block_length'] == 28
    assert block['version'] == (1, 0)
    assert block['section_length'] == -1
    assert block['options_raw'] == ''


def test_read_section_header_little_endian():
    data = io.BytesIO(
        '\x0a\x0d\x0d\x0a'  # magic number
        '\x1c\x00\x00\x00'  # block length (28 bytes)
        '\x4d\x3c\x2b\x1a'  # byte order magic [it's big endian!]
        '\x01\x00\x00\x00'  # version 1.0
        '\xff\xff\xff\xff\xff\xff\xff\xff'  # section length unknown
        ''  # no options here!
        '\x1c\x00\x00\x00')  # block length, again

    block = read_section_header(data)
    assert block['endianness'] == '<'
    assert block['block_length'] == 28
    assert block['version'] == (1, 0)
    assert block['section_length'] == -1
    assert block['options_raw'] == ''


def test_read_section_header_bad_magic():
    data = io.BytesIO('\x0B\xAD\xBE\xEF')
    with pytest.raises(BadMagic) as ctx:
        read_section_header(data)

    assert ctx.value.message == (
        'Invalid magic number: got 0x0BADBEEF, expected 0x0A0D0D0A')


def test_read_section_header_bad_order_magic():
    data = io.BytesIO(
        '\x0a\x0d\x0d\x0a'  # magic number
        '\x1c\x00\x00\x00'  # block length (28 bytes)
        '\x0B\xAD\xBE\xEF'  # byte order magic [it's big endian!]
        '\x01\x00\x00\x00'  # version 1.0
        '\xff\xff\xff\xff\xff\xff\xff\xff'  # section length unknown
        ''  # no options here!
        '\x1c\x00\x00\x00')  # block length, again

    with pytest.raises(BadMagic) as ctx:
        read_section_header(data)

    assert ctx.value.message == (
        'Wrong byte order magic: got 0x0BADBEEF, '
        'expected 0x1A2B3C4D or 0x4D3C2B1A')


def test_read_section_header_mismatching_lengths():
    data = io.BytesIO(
        '\x0a\x0d\x0d\x0a'  # magic number
        '\x00\x00\x00\x1c'  # block length (28 bytes)
        '\x1a\x2b\x3c\x4d'  # byte order magic [it's big endian!]
        '\x00\x01\x00\x00'  # version 1.0
        '\xff\xff\xff\xff\xff\xff\xff\xff'  # section length unknown
        ''  # no options here!
        '\x00\x00\x00\x00')  # block length, again but WRONG!

    with pytest.raises(CorruptedFile) as ctx:
        read_section_header(data)

    assert ctx.value.message == 'Mismatching block lengths: 28 and 0'


def test_read_block_data_big_endian():
    # No need for padding; size = 4 bytes (size 0x10)
    data = io.BytesIO('\x00\x00\x00\x10' '1234' '\x00\x00\x00\x10')
    assert read_block_data(data, '>') == '1234'

    # Base size: 0x0c (12); payload size: 0x05; total: 0x11 (17)
    data = io.BytesIO('\x00\x00\x00\x11' '12345XXX' '\x00\x00\x00\x11')
    assert read_block_data(data, '>') == '12345'


def test_read_block_data_little_endian():
    # No need for padding; size = 4 bytes (size 0x10)
    data = io.BytesIO('\x10\x00\x00\x00' '1234' '\x10\x00\x00\x00\x10')
    assert read_block_data(data, '<') == '1234'

    # Base size: 0x0c (12); payload size: 0x05; total: 0x11 (17)
    data = io.BytesIO('\x11\x00\x00\x00' '12345XXX' '\x11\x00\x00\x00')
    assert read_block_data(data, '<') == '12345'


def test_read_block_data_mismatching_lengths():
    data = io.BytesIO('\x00\x00\x00\x11' '12345XXX' '\xff\x00\x00\x11')
    with pytest.raises(CorruptedFile) as ctx:
        read_block_data(data, '>')

    assert ctx.value.message == 'Mismatching block lengths: 17 and 4278190097'


def test_read_bytes():
    data = io.BytesIO('foobar')
    assert read_bytes(data, 3) == 'foo'
    assert read_bytes(data, 3) == 'bar'

    data = io.BytesIO('foo')
    with pytest.raises(TruncatedFile):
        read_bytes(data, 4)

    data = io.BytesIO('')
    with pytest.raises(StreamEmpty):
        read_bytes(data, 4)

    data = io.BytesIO('')
    assert read_bytes(data, 0) == ''


def test_read_bytes_padded():
    data = io.BytesIO('spam')
    assert read_bytes_padded(data, 4) == 'spam'

    data = io.BytesIO('spameggsbaconXXX')
    assert read_bytes_padded(data, 4) == 'spam'
    assert read_bytes_padded(data, 4) == 'eggs'
    assert read_bytes_padded(data, 5) == 'bacon'

    data = io.BytesIO('fooXbarX')
    assert data.tell() == 0
    assert read_bytes_padded(data, 3) == 'foo'
    assert data.tell() == 4
    assert read_bytes_padded(data, 3) == 'bar'

    data = io.BytesIO('foobar')
    data.read(1)
    assert data.tell() == 1
    with pytest.raises(RuntimeError):
        read_bytes_padded(data, 3)


def test_decode_simple_struct():
    schema = [
        ('rawbytes', RawBytes(12)),
        ('int32s', IntField(32, True)),
        ('int32u', IntField(32, False)),
        ('int16s', IntField(16, True)),
        ('int16u', IntField(16, False)),
    ]

    stream = io.BytesIO()
    stream.write('Hello world!')
    stream.write(struct.pack('>i', -1234))
    stream.write(struct.pack('>I', 1234))
    stream.write(struct.pack('>h', -789))
    stream.write(struct.pack('>H', 789))

    stream.seek(0)
    decoded = struct_decode(schema, stream, '>')

    assert decoded['rawbytes'] == 'Hello world!'
    assert decoded['int32s'] == -1234
    assert decoded['int32u'] == 1234
    assert decoded['int16s'] == -789
    assert decoded['int16u'] == 789


def test_read_options():
    data = io.BytesIO(
        '\x00\x01\x00\x0cHello world!'
        '\x00\x01\x00\x0fSpam eggs bacon\x00'
        '\x00\x02\x00\x0fSome other text\x00'
        '\x00\x00\x00\x00')

    options = read_options(data, '>')
    assert options == [
        (1, 'Hello world!'),
        (1, 'Spam eggs bacon'),
        (2, 'Some other text'),
    ]


def test_options_object():
    schema = [
        (2, 'spam'),
        (3, 'eggs', lambda x: struct.unpack('>I', x)[0]),
        (4, 'bacon', lambda x: unicode(x, encoding='utf-8')),
        (5, 'missing'),
    ]

    raw_options = [
        (1, 'Comment #1'),
        (1, 'Comment #2'),
        (2, 'I love spam spam spam!'),
        (3, '\x00\x00\x01\x00'),
        (4, 'Bacon is delicious!'),
        (20, 'Something different'),
    ]

    options = Options(schema, raw_options)

    assert options['opt_comment'] == 'Comment #1'
    assert options[1] == 'Comment #1'
    assert options.getall('opt_comment') == ['Comment #1', 'Comment #2']
    assert isinstance(options['opt_comment'], unicode)

    assert options['spam'] == 'I love spam spam spam!'
    assert isinstance(options['spam'], bytes)

    assert options['eggs'] == 0x100
    assert isinstance(options['eggs'], (int, long))

    assert options['bacon'] == u'Bacon is delicious!'
    assert isinstance(options['bacon'], unicode)

    with pytest.raises(KeyError):
        options['missing']

    with pytest.raises(KeyError):
        options[5]

    with pytest.raises(KeyError):
        options['Something completely missing']

    with pytest.raises(KeyError):
        options[12345]

    assert options[20] == 'Something different'

    # Check length / keys
    assert len(options) == 5
    assert sorted(options.iterkeys()) == sorted([
        'opt_comment', 'spam', 'eggs', 'bacon', 20])


def test_unpack_dummy_packet():
    schema = [
        ('a_string', RawBytes(8)),
        ('a_number', IntField(32, False)),
        ('options', OptionsField([])),
        ('packet_data', PacketDataField()),
        ('simple_packet_data', SimplePacketDataField()),
        ('name_res', ListField(NameResolutionRecordField())),
        ('another_number', IntField(32, False)),
    ]

    # Note: NULLs are for padding!
    data = io.BytesIO(
        '\x01\x23\x45\x67\x89\xab\xcd\xef'
        '\x00\x00\x01\x00'

        # Options
        '\x00\x01\x00\x0cHello world!'
        '\x00\x01\x00\x0fSpam eggs bacon\x00'
        '\x00\x02\x00\x0fSome other text\x00'
        '\x00\x00\x00\x00'

        # Enhanced Packet data
        '\x00\x00\x00\x12'
        '\x00\x01\x00\x00'
        'These are 18 bytes\x00\x00'

        # Simple packet data
        '\x00\x00\x00\x0d'
        'Simple packet\x00\x00\x00'

        # List of name resolution items
        '\x00\x01'  # IPv4
        '\x00\x13'  # Length: 19bytes
        '\x0a\x22\x33\x44www.example.com\x00'  # 19 bytes (10.34.51.68)

        '\x00\x01'  # IPv4
        '\x00\x13'  # Length: 19bytes
        '\xc0\xa8\x14\x01www.example.org\x00'  # 19 bytes (192.168.20.1)

        '\x00\x02'  # IPv6
        '\x00\x1e'  # 30 bytes
        '\x00\x11\x22\x33\x44\x55\x66\x77'
        '\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        'v6.example.net\x00\x00'

        '\x00\x00\x00\x00'  # End marker

        # Another number, to check end
        '\xaa\xbb\xcc\xdd'
    )

    unpacked = struct_decode(schema, data, endianness='>')
    assert unpacked['a_string'] == '\x01\x23\x45\x67\x89\xab\xcd\xef'
    assert unpacked['a_number'] == 0x100

    assert isinstance(unpacked['options'], Options)
    assert len(unpacked['options']) == 2
    assert unpacked['options']['opt_comment'] == 'Hello world!'
    assert unpacked['options'][2] == 'Some other text'

    assert unpacked['packet_data'] == (0x12, 0x10000, 'These are 18 bytes')

    assert unpacked['simple_packet_data'] == (13, 'Simple packet')

    assert unpacked['name_res'] == [
        {'address': '\x0a\x22\x33\x44', 'name': 'www.example.com', 'type': 1},
        {'address': '\xc0\xa8\x14\x01', 'name': 'www.example.org', 'type': 1},
        {'type': 2,
         'address': '\x00\x11\x22\x33\x44\x55\x66\x77'
                    '\x88\x99\xaa\xbb\xcc\xdd\xee\xff',
         'name': 'v6.example.net'}]
