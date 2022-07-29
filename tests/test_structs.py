"""
Test unpacking structs
"""

import io
import struct

import pytest

from pcapng.exceptions import BadMagic, CorruptedFile, StreamEmpty, TruncatedFile
from pcapng.structs import (
    IntField,
    ListField,
    NameResolutionRecordField,
    Option,
    Options,
    OptionsField,
    PacketBytes,
    RawBytes,
    read_block_data,
    read_bytes,
    read_bytes_padded,
    read_int,
    read_options,
    read_section_header,
    struct_decode,
)


def test_read_int():
    # 16bit, signed, positive
    assert read_int(io.BytesIO(b"\x12\x34"), 16, True, ">") == 0x1234
    assert read_int(io.BytesIO(b"\x12\x34"), 16, True, "<") == 0x3412

    assert read_int(io.BytesIO(b"\x12\x34extra"), 16, True, ">") == 0x1234
    assert read_int(io.BytesIO(b"\x12\x34extra"), 16, True, "<") == 0x3412

    # 16bit, signed, negative
    assert read_int(io.BytesIO(b"\xed\xcc"), 16, True, ">") == -0x1234
    assert read_int(io.BytesIO(b"\xcc\xed"), 16, True, "<") == -0x1234

    assert read_int(io.BytesIO(b"\xed\xccextra"), 16, True, ">") == -0x1234
    assert read_int(io.BytesIO(b"\xcc\xedextra"), 16, True, "<") == -0x1234

    # 16bit, unsigned
    assert read_int(io.BytesIO(b"\x12\x34"), 16, False, ">") == 0x1234
    assert read_int(io.BytesIO(b"\x12\x34"), 16, False, "<") == 0x3412

    assert read_int(io.BytesIO(b"\x12\x34extra"), 16, False, ">") == 0x1234
    assert read_int(io.BytesIO(b"\x12\x34extra"), 16, False, "<") == 0x3412

    # ..do we really need to test other sizes?
    assert (
        read_int(io.BytesIO(b"\x12\x34\x56\x78"), 32, False, ">") == 0x12345678
    )  # noqa
    assert (
        read_int(io.BytesIO(b"\x12\x34\x56\x78"), 32, False, "<") == 0x78563412
    )  # noqa
    assert (
        read_int(io.BytesIO(b"\x12\x34\x56\x78"), 32, True, ">") == 0x12345678
    )  # noqa
    assert (
        read_int(io.BytesIO(b"\x12\x34\x56\x78"), 32, True, "<") == 0x78563412
    )  # noqa


def test_read_int_empty_stream():
    with pytest.raises(StreamEmpty):
        read_int(io.BytesIO(b""), 32)


def test_read_int_truncated_stream():
    with pytest.raises(TruncatedFile):
        read_int(io.BytesIO(b"AB"), 32)


def test_read_section_header_big_endian():
    data = io.BytesIO(
        # '\x0a\x0d\x0d\x0a'  # magic number has already been read..
        b"\x00\x00\x00\x1c"  # block length (28 bytes)
        b"\x1a\x2b\x3c\x4d"  # byte order magic [it's big endian!]
        b"\x00\x01\x00\x00"  # version 1.0
        b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section length unknown
        b""  # no options here!
        b"\x00\x00\x00\x1c"
    )  # block length, again

    block = read_section_header(data)
    assert block["endianness"] == ">"
    assert block["data"] == b"\x00\x01\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"


def test_read_section_header_little_endian():
    data = io.BytesIO(
        # '\x0a\x0d\x0d\x0a'  # magic number
        b"\x1c\x00\x00\x00"  # block length (28 bytes)
        b"\x4d\x3c\x2b\x1a"  # byte order magic [it's big endian!]
        b"\x01\x00\x00\x00"  # version 1.0
        b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section length unknown
        b""  # no options here!
        b"\x1c\x00\x00\x00"
    )  # block length, again

    block = read_section_header(data)
    assert block["endianness"] == "<"
    assert block["data"] == b"\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"


def test_read_section_header_bad_order_magic():
    data = io.BytesIO(
        # '\x0a\x0d\x0d\x0a'  # magic number
        b"\x1c\x00\x00\x00"  # block length (28 bytes)
        b"\x0B\xAD\xBE\xEF"  # byte order magic [it's big endian!]
        b"\x01\x00\x00\x00"  # version 1.0
        b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section length unknown
        b""  # no options here!
        b"\x1c\x00\x00\x00"
    )  # block length, again

    with pytest.raises(BadMagic) as ctx:
        read_section_header(data)

    assert str(ctx.value) == (
        "Wrong byte order magic: got 0x0BADBEEF, " "expected 0x1A2B3C4D or 0x4D3C2B1A"
    )


def test_read_section_header_mismatching_lengths():
    data = io.BytesIO(
        # '\x0a\x0d\x0d\x0a'  # magic number
        b"\x00\x00\x00\x1c"  # block length (28 bytes)
        b"\x1a\x2b\x3c\x4d"  # byte order magic [it's big endian!]
        b"\x00\x01\x00\x00"  # version 1.0
        b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section length unknown
        b""  # no options here!
        b"\x00\x00\x00\x00"
    )  # block length, again but WRONG!

    with pytest.raises(CorruptedFile) as ctx:
        read_section_header(data)

    assert str(ctx.value) == "Mismatching block lengths: 28 and 0"


def test_read_block_data_big_endian():
    # No need for padding; size = 4 bytes (size 0x10)
    data = io.BytesIO(b"\x00\x00\x00\x10" b"1234" b"\x00\x00\x00\x10")
    assert read_block_data(data, ">") == b"1234"

    # Base size: 0x0c (12); payload size: 0x05; total: 0x11 (17)
    data = io.BytesIO(b"\x00\x00\x00\x11" b"12345XXX" b"\x00\x00\x00\x11")
    assert read_block_data(data, ">") == b"12345"


def test_read_block_data_little_endian():
    # No need for padding; size = 4 bytes (size 0x10)
    data = io.BytesIO(b"\x10\x00\x00\x00" b"1234" b"\x10\x00\x00\x00\x10")
    assert read_block_data(data, "<") == b"1234"

    # Base size: 0x0c (12); payload size: 0x05; total: 0x11 (17)
    data = io.BytesIO(b"\x11\x00\x00\x00" b"12345XXX" b"\x11\x00\x00\x00")
    assert read_block_data(data, "<") == b"12345"


def test_read_block_data_mismatching_lengths():
    data = io.BytesIO(b"\x00\x00\x00\x11" b"12345XXX" b"\xff\x00\x00\x11")
    with pytest.raises(CorruptedFile) as ctx:
        read_block_data(data, ">")

    assert str(ctx.value) == "Mismatching block lengths: 17 and 4278190097"


def test_read_bytes():
    data = io.BytesIO(b"foobar")
    assert read_bytes(data, 3) == b"foo"
    assert read_bytes(data, 3) == b"bar"

    data = io.BytesIO(b"foo")
    with pytest.raises(TruncatedFile):
        read_bytes(data, 4)

    data = io.BytesIO(b"")
    with pytest.raises(StreamEmpty):
        read_bytes(data, 4)

    data = io.BytesIO(b"")
    assert read_bytes(data, 0) == b""


def test_read_bytes_padded():
    data = io.BytesIO(b"spam")
    assert read_bytes_padded(data, 4) == b"spam"

    data = io.BytesIO(b"spameggsbaconXXX")
    assert read_bytes_padded(data, 4) == b"spam"
    assert read_bytes_padded(data, 4) == b"eggs"
    assert read_bytes_padded(data, 5) == b"bacon"

    data = io.BytesIO(b"fooXbarX")
    assert data.tell() == 0
    assert read_bytes_padded(data, 3) == b"foo"
    assert data.tell() == 4
    assert read_bytes_padded(data, 3) == b"bar"

    data = io.BytesIO(b"foobar")
    data.read(1)
    assert data.tell() == 1
    with pytest.raises(RuntimeError):
        read_bytes_padded(data, 3)


def test_decode_simple_struct():
    schema = [
        ("rawbytes", RawBytes(12), b""),
        ("int32s", IntField(32, True), 0),
        ("int32u", IntField(32, False), 0),
        ("int16s", IntField(16, True), 0),
        ("int16u", IntField(16, False), 0),
    ]

    stream = io.BytesIO()
    stream.write(b"Hello world!")
    stream.write(struct.pack(">i", -1234))
    stream.write(struct.pack(">I", 1234))
    stream.write(struct.pack(">h", -789))
    stream.write(struct.pack(">H", 789))

    stream.seek(0)
    decoded = struct_decode(schema, stream, ">")

    assert decoded["rawbytes"] == b"Hello world!"
    assert decoded["int32s"] == -1234
    assert decoded["int32u"] == 1234
    assert decoded["int16s"] == -789
    assert decoded["int16u"] == 789


def test_read_options():
    data = io.BytesIO(
        b"\x00\x01\x00\x0cHello world!"
        b"\x00\x01\x00\x0fSpam eggs bacon\x00"
        b"\x00\x02\x00\x0fSome other text\x00"
        b"\x00\x00\x00\x00"
    )

    options = read_options(data, ">")
    assert options == [
        (1, b"Hello world!"),
        (1, b"Spam eggs bacon"),
        (2, b"Some other text"),
    ]


def test_read_options_2():
    data = io.BytesIO(
        b"\x00\x01\x00\x0e"
        b"Just a comment\x00\x00"
        b"\x00\x02\x00\x0b"
        b"My Computer\x00"
        b"\x00\x03\x00\x05"
        b"My OS\x00\x00\x00"
        b"\x00\x04\x00\x0a"
        b"A fake app\x00\x00"
        b"\x00\x00\x00\x00"
    )

    options = read_options(data, ">")
    assert options == [
        (1, b"Just a comment"),
        (2, b"My Computer"),
        (3, b"My OS"),
        (4, b"A fake app"),
    ]


def test_options_object():
    schema = [
        Option(2, "spam", "bytes"),
        Option(3, "eggs", "u32"),
        Option(4, "bacon", "string"),
        Option(5, "missing"),
    ]

    raw_options = [
        (1, b"Comment #1"),
        (1, b"Comment #2"),
        (2, b"I love spam spam spam!"),
        (3, b"\x00\x00\x01\x00"),
        (4, b"Bacon is delicious!"),
        (20, b"Something different"),
        (2988, b"\x00\x00\x00\x01Some Custom Data"),
        (2989, b"\x00\x00\x00\x01\x01\x02"),
    ]

    options = Options(schema=schema, data=raw_options, endianness=">")

    assert options["opt_comment"] == "Comment #1"
    assert options[1] == "Comment #1"
    assert options.get_all("opt_comment") == ["Comment #1", "Comment #2"]
    assert isinstance(options["opt_comment"], str)

    assert options["spam"] == b"I love spam spam spam!"
    assert isinstance(options["spam"], bytes)

    assert options["eggs"] == 0x100
    assert isinstance(options["eggs"], int)

    assert options["bacon"] == "Bacon is delicious!"
    assert isinstance(options["bacon"], str)

    assert options["custom_str_safe"] == (1, "Some Custom Data")
    assert isinstance(options["custom_str_safe"][0], int)
    assert isinstance(options["custom_str_safe"][1], str)

    assert options["custom_bytes_safe"] == (1, b"\x01\x02")
    assert isinstance(options["custom_bytes_safe"][0], int)
    assert isinstance(options["custom_bytes_safe"][1], bytes)

    with pytest.raises(KeyError):
        options["missing"]

    with pytest.raises(KeyError):
        options[8]

    with pytest.raises(KeyError):
        options["Something completely missing"]

    with pytest.raises(KeyError):
        options[12345]

    assert options[20] == b"Something different"

    # Check length / keys
    assert len(options) == 7
    assert set(options.keys()) == set(
        [
            "opt_comment",
            "spam",
            "eggs",
            "bacon",
            "custom_str_safe",
            "custom_bytes_safe",
            20,
        ]
    )

    # Check "in" and "not in"
    assert "opt_comment" in options
    assert "spam" in options
    assert "eggs" in options
    assert "bacon" in options
    assert "custom_str_safe" in options
    assert "custom_bytes_safe" in options
    assert 20 in options
    assert "missing" not in options
    assert "something different" not in options

    assert 1 in options
    assert 2 in options
    assert 3 in options
    assert 4 in options
    assert 2988 in options
    assert 2989 in options
    assert 5 not in options
    assert 12345 not in options


def test_unpack_dummy_packet():
    schema = [
        ("a_string", RawBytes(8), ""),
        ("a_number", IntField(32, False), 0),
        ("options", OptionsField([]), None),
        ("pb_captured_len", IntField(32, False), 0),
        ("pb_orig_len", IntField(32, False), 0),
        ("packet_data", PacketBytes("pb_captured_len"), b""),
        ("spb_orig_len", IntField(32, False), 0),
        ("simple_packet_data", PacketBytes("spb_orig_len"), b""),
        ("name_res", ListField(NameResolutionRecordField()), []),
        ("another_number", IntField(32, False), 0),
    ]

    # Note: NULLs are for padding!
    data = io.BytesIO(
        b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        b"\x00\x00\x01\x00"
        # Options
        b"\x00\x01\x00\x0cHello world!"
        b"\x00\x01\x00\x0fSpam eggs bacon\x00"
        b"\x00\x02\x00\x0fSome other text\x00"
        b"\x00\x00\x00\x00"
        # Enhanced Packet data
        b"\x00\x00\x00\x12"
        b"\x00\x01\x00\x00"
        b"These are 18 bytes\x00\x00"
        # Simple packet data
        b"\x00\x00\x00\x0d"
        b"Simple packet\x00\x00\x00"
        # List of name resolution items
        b"\x00\x01"  # IPv4
        b"\x00\x13"  # Length: 19bytes
        b"\x0a\x22\x33\x44www.example.com\x00"  # 19 bytes (10.34.51.68)
        b"\x00\x01"  # IPv4
        b"\x00\x13"  # Length: 19bytes
        b"\xc0\xa8\x14\x01www.example.org\x00"  # 19 bytes (192.168.20.1)
        b"\x00\x02"  # IPv6
        b"\x00\x1e"  # 30 bytes
        b"\x00\x11\x22\x33\x44\x55\x66\x77"
        b"\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
        b"v6.example.net\x00\x00"
        b"\x00\x00\x00\x00"  # End marker
        # Another number, to check end
        b"\xaa\xbb\xcc\xdd"
    )

    unpacked = struct_decode(schema, data, endianness=">")
    assert unpacked["a_string"] == b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    assert unpacked["a_number"] == 0x100

    assert isinstance(unpacked["options"], Options)
    assert len(unpacked["options"]) == 2
    assert unpacked["options"]["opt_comment"] == "Hello world!"
    assert unpacked["options"][2] == b"Some other text"

    assert unpacked["pb_captured_len"] == 0x12
    assert unpacked["pb_orig_len"] == 0x10000
    assert unpacked["packet_data"] == b"These are 18 bytes"

    assert unpacked["spb_orig_len"] == 13
    assert unpacked["simple_packet_data"] == b"Simple packet"

    assert unpacked["name_res"] == [
        {"address": "10.34.51.68", "names": ["www.example.com"], "type": 1},
        {"address": "192.168.20.1", "names": ["www.example.org"], "type": 1},
        {
            "type": 2,
            "address": "11:2233:4455:6677:8899:aabb:ccdd:eeff",
            "names": ["v6.example.net"],
        },
    ]
