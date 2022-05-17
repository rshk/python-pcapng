import pytest

from pcapng.blocks import InterfaceDescription, ObsoletePacket, SectionHeader
from pcapng.scanner import FileScanner


def test_sample_test001_ntar():
    with open("test_data/test001.ntar", "rb") as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # There is just a section header
        assert len(blocks) == 1

        assert blocks[0].endianness == "<"
        assert blocks[0].version == (1, 0)
        assert blocks[0].length == -1
        assert len(blocks[0].options) == 0
        assert len(blocks[0].interfaces) == 0


def test_sample_test002_ntar():
    with open("test_data/test002.ntar", "rb") as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # Section header, interface description
        assert len(blocks) == 2

        assert isinstance(blocks[0], SectionHeader)
        assert blocks[0].endianness == "<"
        assert blocks[0].version == (1, 0)
        assert blocks[0].length == -1
        assert len(blocks[0].options) == 0
        assert len(blocks[0].interfaces) == 1

        assert isinstance(blocks[1], InterfaceDescription)
        assert blocks[1].link_type == 0  # Unknown link type
        assert blocks[1].snaplen == 0
        assert len(blocks[1].options) == 0


def test_sample_test003_ntar():
    with open("test_data/test003.ntar", "rb") as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # Section header, interface description
        assert len(blocks) == 2

        assert isinstance(blocks[0], SectionHeader)
        assert blocks[0].endianness == "<"
        assert blocks[0].version == (1, 0)
        assert blocks[0].length == -1
        assert len(blocks[0].options) == 0
        assert len(blocks[0].interfaces) == 1

        assert isinstance(blocks[1], InterfaceDescription)
        assert blocks[1].link_type == 0x04D8  # ???
        assert blocks[1].snaplen == 0x7C
        assert len(blocks[1].options) == 0


def test_sample_test004_ntar():
    with open("test_data/test004.ntar", "rb") as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # Section header
        assert len(blocks) == 1

        assert isinstance(blocks[0], SectionHeader)
        assert blocks[0].endianness == "<"
        assert blocks[0].version == (1, 0)
        assert blocks[0].length == -1

        assert len(blocks[0].options) == 2
        assert blocks[0].options["shb_os"] == "Windows XP\x00"  # (why NULL?)
        assert blocks[0].options["shb_userappl"] == "Test004.exe\x00"

        assert len(blocks[0].interfaces) == 0


def test_sample_test005_ntar():
    with open("test_data/test005.ntar", "rb") as fp:
        scanner = FileScanner(fp)
        blocks = list(scanner)

        # Section header, interface description
        assert len(blocks) == 2

        assert isinstance(blocks[0], SectionHeader)
        assert blocks[0].endianness == "<"
        assert blocks[0].version == (1, 0)
        assert blocks[0].length == -1
        assert len(blocks[0].options) == 0
        assert len(blocks[0].interfaces) == 1

        assert isinstance(blocks[1], InterfaceDescription)
        assert blocks[1].link_type == 0x04D8  # ???
        assert blocks[1].snaplen == 0x7C
        assert len(blocks[1].options) == 2

        assert (
            blocks[1].options.get_raw("if_speed") == b"\x00\xe4\x0b\x54\x02\x00\x00\x00"
        )  # noqa
        assert blocks[1].options["if_speed"] == 0x00000002540BE400
        assert blocks[1].options["if_speed"] == (10**10)  # 10Gbit

        assert blocks[1].options["if_description"] == "Stupid ethernet interface\x00"


@pytest.mark.parametrize(
    "filename",
    [
        pytest.param("test_data/test006.ntar", marks=pytest.mark.xfail),
        "test_data/test006-fixed.ntar",
    ],
)
def test_sample_test006_ntar(filename):

    # Note: See the comment below this function
    # test006.ntar is reporting an incorrect size, which causes the
    # test to fail. Is this the expected behavior?

    with open(filename, "rb") as fp:
        scanner = FileScanner(fp)

        blocks = list(scanner)

        # Section header, interface description, then what??
        assert len(blocks) == 3

        assert isinstance(blocks[0], SectionHeader)
        assert blocks[0].endianness == "<"
        assert blocks[0].version == (1, 0)
        assert blocks[0].length == -1
        assert len(blocks[0].options) == 0
        assert len(blocks[0].interfaces) == 1

        assert isinstance(blocks[1], InterfaceDescription)
        assert blocks[1].link_type == 2
        assert blocks[1].snaplen == 96
        assert len(blocks[1].options) == 2

        assert blocks[1].options["if_speed"] == (10**8)  # 100Mbit

        assert blocks[1].options["if_description"] == "Stupid ethernet interface\x00"

        assert isinstance(blocks[2], ObsoletePacket)
        assert blocks[2].interface_id == 0
        assert blocks[2].options["pack_flags"].inout == "NA"
        assert blocks[2].options["pack_flags"].casttype == "NA"
        assert blocks[2].options["pack_flags"].fcslen == 0
        assert blocks[2].options["pack_flags"].reserved == 0
        assert blocks[2].options["pack_flags"].err_16 is False
        assert blocks[2].options["pack_flags"].err_17 is False
        assert blocks[2].options["pack_flags"].err_18 is False
        assert blocks[2].options["pack_flags"].err_19 is False
        assert blocks[2].options["pack_flags"].err_20 is False
        assert blocks[2].options["pack_flags"].err_21 is False
        assert blocks[2].options["pack_flags"].err_22 is False
        assert blocks[2].options["pack_flags"].err_23 is False
        assert blocks[2].options["pack_flags"].err_crc is False
        assert blocks[2].options["pack_flags"].err_long is False
        assert blocks[2].options["pack_flags"].err_short is False
        assert blocks[2].options["pack_flags"].err_frame_gap is False
        assert blocks[2].options["pack_flags"].err_frame_align is False
        assert blocks[2].options["pack_flags"].err_frame_delim is False
        assert blocks[2].options["pack_flags"].err_preamble is False
        assert blocks[2].options["pack_flags"].err_symbol is False


# ============================================================
# Dissection of test006.ntar
#
# PROBLEM: Total size of packet block is incorrectly reported
#          to be one byte shorter than it actually is!
# ============================================================

# -------------------- Section header --------------------

# 00000000: 0a0d 0d0a                                Magic number
# 00000000:           1c00 0000                      Block size (28)
# 00000000:                     4d3c 2b1a            Byte order (LE)
# 00000000:                               0100 0000  Version (1, 0)
# 00000010: ffff ffff ffff ffff                      Section size (-1)
#                                                    (No options)
# 00000010:                     1c00 0000            Block size (28)

# -------------------- Interface description --------------------

# 00000010:                               0100 0000  Block Magic

# 00000020: 4400 0000                                Block total length (68)
# 00000020:           0200                           Link type (2)
# 00000020:                0000                      Reserved (0)
# 00000020:                     6000 0000            Snapshot length

# 00000020:                               0300 1a00  Option 3 - 26 bytes
# 00000030: 5374 7570 6964 2065 7468 6572 6e65 7420  Stupid ethernet
# 00000040: 696e 7465 7266 6163 6500 0000            interface

# 00000040:                               0800 0800  Option 8 - 8 bytes
# 00000050: 00e1 f505 0000 0000                      (speed = 100Mbps)

# 00000050:                     0000 0000            End of options block
# 00000050:                               4400 0000  Block total length (68)

# -------------------- Packet (Obsolete) --------------------

# 00000060: 0200 0000                                Block Magic
# 00000060:           a700 0000                      Block size (167(!??))
# 00000060:                     0000                 Interface id (0)
# 00000060:                          0000            Drops count
# 00000060:                               0000 0000  Timestamp (high)
# 00000070: 0000 0000                                Timestamp (low)
# 00000070:           7b00 0000                      Captured len (123) [pad 1]
# 00000070:                     e803 0000            Packet len (1000)

# 00000070:                               6853 11f3  ....{.......hS.. [4]
# 00000080: 3b00 0000 978f 00f3 3b00 0000 0000 0000  ;.......;....... [20]
# 00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................ [36]
# 000000a0: 0000 0000 0100 0000 0000 0000 d0f1 ffbf  ................ [52]
# 000000b0: 7f00 0000 d04f 11f3 3b00 0000 6005 00f3  .....O..;...`... [68]
# 000000c0: 3b00 0000 fc06 00f3 3b00 0000 6002 00f3  ;.......;...`... [84]
# 000000d0: 3b00 0000 5806 4000 0000 0000 6853 11f3  ;...X.@.....hS.. [100]
# 000000e0: 3b00 0000 6853 11f3 0200 0000 0000 0000  ;...hS.......... [116]
# 000000f0: 0000 0000 0000 0000                      ................ [124]

# 000000f0:                     0200 0400            Option 2 - 4 bytes
# 000000f0:                               0000 0000  0x00000000
# 00000100: 0000 0000                                Options end marker

# 00000100:           a700 0000                      Block size (167)


def test_sample_test007_ntar():
    with open("test_data/test007.ntar", "rb") as fp:
        scanner = FileScanner(fp)
        for entry in scanner:
            pass


def test_sample_test008_ntar():
    with open("test_data/test008.ntar", "rb") as fp:
        scanner = FileScanner(fp)
        for entry in scanner:
            pass


def test_sample_test009_ntar():
    with open("test_data/test009.ntar", "rb") as fp:
        scanner = FileScanner(fp)
        for entry in scanner:
            pass


def test_sample_test010_ntar():
    with open("test_data/test010.ntar", "rb") as fp:
        scanner = FileScanner(fp)
        for entry in scanner:
            pass
