import io

from pcapng.blocks import SectionHeader
from pcapng.scanner import FileScanner
from pcapng.structs import Options


def test_read_block_sectionheader_bigendian_empty_options():
    scanner = FileScanner(io.BytesIO(
        "\x0a\x0d\x0d\x0a"  # Magic number
        "\x00\x00\x00\x20"  # Block size (32 bytes)
        "\x1a\x2b\x3c\x4d"  # Magic number
        "\x00\x01\x00\x00"  # Version
        "\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
        "\x00\x00\x00\x00"  # Empty options
        "\x00\x00\x00\x20"  # Block size (32 bytes)
    ))

    blocks = list(scanner)
    assert len(blocks) == 1
    block = blocks[0]

    assert isinstance(block, SectionHeader)
    assert block.endianness == '>'
    assert block.version == (1, 0)
    assert block.length == -1
    assert isinstance(block.options, Options)
    assert len(block.options) == 0
    assert block.interfaces == {}


def test_read_block_sectionheader_littleendian_empty_options():
    scanner = FileScanner(io.BytesIO(
        "\x0a\x0d\x0d\x0a"  # Magic number
        "\x20\x00\x00\x00"  # Block size (32 bytes)
        "\x4d\x3c\x2b\x1a"  # Magic number
        "\x01\x00\x00\x00"  # Version
        "\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
        "\x00\x00\x00\x00"  # Empty options
        "\x20\x00\x00\x00"  # Block size (32 bytes)
    ))

    blocks = list(scanner)
    assert len(blocks) == 1
    block = blocks[0]

    assert isinstance(block, SectionHeader)
    assert block.endianness == '<'
    assert block.version == (1, 0)
    assert block.length == -1
    assert isinstance(block.options, Options)
    assert len(block.options) == 0
    assert block.interfaces == {}


def test_read_block_sectionheader_bigendian_missing_options():
    scanner = FileScanner(io.BytesIO(
        "\x0a\x0d\x0d\x0a"  # Magic number
        "\x00\x00\x00\x1c"  # Block size (32 bytes)
        "\x1a\x2b\x3c\x4d"  # Byte order
        "\x00\x01\x00\x00"  # Version
        "\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
        ""  # Missing options
        "\x00\x00\x00\x1c"  # Block size (32 bytes)
    ))

    blocks = list(scanner)
    assert len(blocks) == 1
    block = blocks[0]

    assert isinstance(block, SectionHeader)
    assert block.endianness == '>'
    assert block.version == (1, 0)
    assert block.length == -1
    assert isinstance(block.options, Options)
    assert len(block.options) == 0
    assert block.interfaces == {}


def test_read_block_sectionheader_littleendian_missing_options():
    scanner = FileScanner(io.BytesIO(
        "\x0a\x0d\x0d\x0a"  # Magic number
        "\x1c\x00\x00\x00"  # Block size (32 bytes)
        "\x4d\x3c\x2b\x1a"  # Byte order
        "\x01\x00\x00\x00"  # Version
        "\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length
        ""  # Missing options
        "\x1c\x00\x00\x00"  # Block size (32 bytes)
    ))

    blocks = list(scanner)
    assert len(blocks) == 1
    block = blocks[0]

    assert isinstance(block, SectionHeader)
    assert block.endianness == '<'
    assert block.version == (1, 0)
    assert block.length == -1
    assert isinstance(block.options, Options)
    assert len(block.options) == 0
    assert block.interfaces == {}


def test_read_block_sectionheader_bigendian_with_options():
    scanner = FileScanner(io.BytesIO(
        "\x0a\x0d\x0d\x0a"  # Magic number
        "\x00\x00\x00\x60"  # Block size (96 bytes)
        "\x1a\x2b\x3c\x4d"  # Magic number
        "\x00\x01\x00\x00"  # Version
        "\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length

        # Options
        '\x00\x01\x00\x0e''Just a comment\x00\x00'
        '\x00\x02\x00\x0b''My Computer\x00'
        '\x00\x03\x00\x05''My OS\x00\x00\x00'
        '\x00\x04\x00\x0a''A fake app\x00\x00'
        "\x00\x00\x00\x00"

        "\x00\x00\x00\x60"  # Block size (96 bytes)
    ))

    blocks = list(scanner)
    assert len(blocks) == 1
    block = blocks[0]

    assert isinstance(block, SectionHeader)
    assert block.endianness == '>'
    assert block.version == (1, 0)
    assert block.length == -1
    assert isinstance(block.options, Options)
    assert len(block.options) == 4
    assert block.options['opt_comment'] == 'Just a comment'
    assert block.interfaces == {}

    assert repr(block) == (
        "<SectionHeader version=1.0 endianness='>' length=-1 options={0}>"
        .format(repr(block.options)))


def test_read_block_sectionheader_littleendian_with_options():
    scanner = FileScanner(io.BytesIO(
        "\x0a\x0d\x0d\x0a"  # Magic number
        "\x60\x00\x00\x00"  # Block size (96 bytes)
        "\x4d\x3c\x2b\x1a"  # Magic number
        "\x01\x00\x00\x00"  # Version
        "\xff\xff\xff\xff\xff\xff\xff\xff"  # Undefined section length

        # Options
        '\x01\x00\x0e\x00''Just a comment\x00\x00'
        '\x02\x00\x0b\x00''My Computer\x00'
        '\x03\x00\x05\x00''My OS\x00\x00\x00'
        '\x04\x00\x0a\x00''A fake app\x00\x00'
        "\x00\x00\x00\x00"

        "\x60\x00\x00\x00"  # Block size (96 bytes)
    ))

    blocks = list(scanner)
    assert len(blocks) == 1
    block = blocks[0]

    assert isinstance(block, SectionHeader)
    assert block.endianness == '<'
    assert block.version == (1, 0)
    assert block.length == -1
    assert isinstance(block.options, Options)
    assert len(block.options) == 4
    assert block.options['opt_comment'] == 'Just a comment'
    assert block.interfaces == {}

    assert repr(block) == (
        "<SectionHeader version=1.0 endianness='<' length=-1 options={0}>"
        .format(repr(block.options)))
