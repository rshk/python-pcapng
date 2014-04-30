import io

from pcapng.utils import (
    timestamp_pack, timestamp_unpack, aligned_read, aligned_write)


def test_timestamp_packing():
    # Let's create a fake timestamp, in (2**32)ths of second.

    # 6008098994154247168
    # 1398869555  -> seconds
    # 4059173888  -> decimal part

    ts_full = 6008098994154247168
    ts_high = 1398869555
    ts_low = 4059173888

    assert timestamp_unpack(ts_high, ts_low) == ts_full
    assert timestamp_pack(ts_full) == (ts_high, ts_low)

    for number in [20, 1 << 16, 1 << 34]:
        assert timestamp_unpack(*timestamp_pack(number)) == number


def test_aligned_read():
    fp = io.BytesIO('ABCD''EFGH''IJKL''MNOP''QRST''UVWX''YZ01''2345''6789')

    assert fp.tell() == 0
    assert aligned_read(fp, 3, bs=4) == 'ABC'
    assert fp.tell() == 4
    assert aligned_read(fp, 1, bs=4) == 'E'
    assert fp.tell() == 8
    assert aligned_read(fp, 4, bs=4) == 'IJKL'
    assert fp.tell() == 12
    assert aligned_read(fp, 4, bs=4) == 'MNOP'
    assert fp.tell() == 16
    assert aligned_read(fp, 0, bs=4) == ''
    assert fp.tell() == 16


def test_aligned_write():
    fp = io.BytesIO()

    aligned_write(fp, 'A', bs=4)
    aligned_write(fp, 'BB', bs=4)
    aligned_write(fp, 'CCCC', bs=4)
    aligned_write(fp, 'DDDD', bs=4)
    aligned_write(fp, '', bs=4)

    assert fp.getvalue() == 'A\x00\x00\x00''BB\x00\x00''CCCC''DDDD'
