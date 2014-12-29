"""
Tests for errors during parsing
"""

import pytest

from pcapng.blocks import SectionHeader


def test_get_nonexistent_block_attribute():
    shb = SectionHeader(
        '\x00\x01\x00\x00'
        '\xff\xff\xff\xff\xff\xff\xff\xff'
        '\x00\x00\x00\x00',
        endianness='>')

    assert shb.version == (1, 0)  # check that parsing was successful

    with pytest.raises(AttributeError):
        shb.does_not_exist
