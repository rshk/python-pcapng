import io

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.exceptions import PcapngStrictnessError, PcapngStrictnessWarning
from pcapng.strictness import Strictness, set_strictness


def compare_blocklists(list1, list2):
    "Compare two lists of blocks. Helper for the below tests."

    assert len(list1) == len(list2)

    for i in range(0, len(list1)):
        assert list1[i] == list2[i], "block #{} mismatch".format(i)


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_write_read_all_blocks(endianness):
    # Track the blocks we're writing
    out_blocks = []

    # Build our original/output session
    o_shb = blocks.SectionHeader(
        endianness=endianness,
        options={
            "shb_hardware": "pytest",
            "shb_os": "python",
            "shb_userappl": "python-pcapng",
        },
    )
    out_blocks.append(o_shb)

    o_idb = o_shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options={
            "if_name": "Interface Zero",
            "if_description": "Test interface",
            "if_os": "python",
            "if_hardware": "whatever",
            "if_filter": [(0, b"tcp port 23 and host 192.0.2.5")],
        },
    )
    out_blocks.append(o_idb)

    # The SHB and IDBs will be written right away here.
    fake_file = io.BytesIO()
    writer = FileWriter(fake_file, o_shb)

    # Add blocks to the output

    # epb
    blk = o_shb.new_member(blocks.EnhancedPacket)
    blk.packet_data = b"Test data 123 XYZ"
    writer.write_block(blk)
    out_blocks.append(blk)

    # spb
    blk = o_shb.new_member(blocks.SimplePacket)
    blk.packet_data = b"Test data 123 XYZ"
    writer.write_block(blk)
    out_blocks.append(blk)

    # pb (which is obsolete)
    set_strictness(Strictness.FORBID)
    blk = o_shb.new_member(blocks.ObsoletePacket)
    blk.packet_data = b"Test data 123 XYZ"
    with pytest.raises(PcapngStrictnessError, match="obsolete"):
        # Should prevent writing by default
        writer.write_block(blk)

    # Set to warning mode and try again
    set_strictness(Strictness.WARN)
    with pytest.warns(PcapngStrictnessWarning, match="obsolete"):
        # Should write the obsolete block now
        writer.write_block(blk)
    out_blocks.append(blk)

    # Set to fix mode and try again
    set_strictness(Strictness.FIX)
    with pytest.warns(PcapngStrictnessWarning, match="obsolete"):
        # Should write an enhanced block now
        writer.write_block(blk)
    out_blocks.append(blk.enhanced())

    set_strictness(Strictness.FORBID)

    # nrb
    blk = o_shb.new_member(
        blocks.NameResolution,
        records=[
            {
                "type": 1,
                "address": "127.0.0.1",
                "names": ["localhost", "localhost.localdomain"],
            },
            {
                "type": 2,
                "address": "::1",
                "names": ["localhost", "localhost.localdomain"],
            },
        ],
    )
    writer.write_block(blk)
    out_blocks.append(blk)

    # isb
    blk = o_shb.new_member(
        blocks.InterfaceStatistics,
        interface_id=0,
        timestamp_high=0x01234567,
        timestamp_low=0x89ABCDEF,
        options={
            "isb_starttime": 0x0123456789ABCD00,
            "isb_endtime": 0x0123456789ABCDEF,
            "isb_usrdeliv": 50,
        },
    )
    writer.write_block(blk)
    out_blocks.append(blk)

    # Done writing blocks.
    # Now get back what we wrote and see if things line up.
    fake_file.seek(0)
    in_blocks = list(FileScanner(fake_file))

    compare_blocklists(in_blocks, out_blocks)


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_spb_snap_lengths(endianness):
    """
    Simple Packet Blocks present a unique challenge in parsing. The packet does not
    contain an explicit "captured length" indicator, only the original observed
    packet length; one must consult the capturing network interface's snap length
    in order to determine whether the packet may have been truncated.

    The block interface was designed to take care of most of this for the developer,
    both for reading and writing. For reading, the :py:method:`captured_len` is
    a property that works out its value from the capturing interface and the original
    packet length. For writing, packet data will be truncated to the capturing
    interface's snap length if it would be too big.
    """

    # Binary data to write/test
    data = bytes(range(0, 256))

    # First session: no snap length
    o_shb = blocks.SectionHeader(endianness=endianness)
    o_idb = o_shb.new_member(blocks.InterfaceDescription)  # noqa: F841
    o_blk1 = o_shb.new_member(blocks.SimplePacket, packet_data=data)

    fake_file = io.BytesIO()
    writer = FileWriter(fake_file, o_shb)
    writer.write_block(o_blk1)

    fake_file.seek(0)
    (i_shb, i_idb, i_blk1) = list(FileScanner(fake_file))
    assert i_blk1.captured_len == len(data)
    assert i_blk1.packet_len == len(data)
    assert i_blk1.packet_data == data

    # Second session: with snap length
    o_shb = blocks.SectionHeader(endianness=endianness)
    o_idb = o_shb.new_member(blocks.InterfaceDescription, snaplen=32)  # noqa: F841
    o_blk1 = o_shb.new_member(blocks.SimplePacket, packet_data=data[:16])
    o_blk2 = o_shb.new_member(blocks.SimplePacket, packet_data=data[:32])
    o_blk3 = o_shb.new_member(blocks.SimplePacket, packet_data=data[:33])

    fake_file = io.BytesIO()
    writer = FileWriter(fake_file, o_shb)
    writer.write_block(o_blk1)
    writer.write_block(o_blk2)
    writer.write_block(o_blk3)

    fake_file.seek(0)
    (i_shb, i_idb, i_blk1, i_blk2, i_blk3) = list(FileScanner(fake_file))

    assert i_blk1.captured_len == 16
    assert i_blk1.packet_len == 16
    assert i_blk1.packet_data == data[:16]

    assert i_blk2.captured_len == 32
    assert i_blk2.packet_len == 32
    assert i_blk2.packet_data == data[:32]

    assert i_blk3.captured_len == 32
    assert i_blk3.packet_len == 33
    assert i_blk3.packet_data == data[:32]
