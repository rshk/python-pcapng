"""
Test unpacking structs
"""

import io
import struct

import pytest

from pcapng.structs import (
    read_int, read_section_header, read_block_data, read_bytes,
    read_bytes_padded, RawBytes, IntField, struct_decode)
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
