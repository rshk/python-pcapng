"""
Miscellaneous utilities
"""

# Note: timestamps are *not* in seconds / milliseconds / microsecond
#       or any other kind of fixed format. Instead, their resolution
#       depends on the ts_resol field of the interface the packet
#       belongs to.

# Resolution of timestamps. If the Most Significant Bit is equal to
# zero, the remaining bits indicates the resolution of the timestamp
# as as a negative power of 10 (e.g. 6 means microsecond resolution,
# timestamps are the number of microseconds since 1/1/1970). If the
# Most Significant Bit is equal to one, the remaining bits indicates
# the resolution as as negative power of 2 (e.g. 10 means 1/1024 of
# second). If this option is not present, a resolution of 10^-6 is
# assumed (i.e. timestamps have the same resolution of the standard
# 'libpcap' timestamps).


def timestamp_unpack(ts_high, ts_low):
    return (ts_high << 32) + ts_low


def timestamp_pack(timestamp):
    return (timestamp >> 32), (timestamp % (1 << 32))


def aligned_read(fp, size, bs=4):
    """
    Read ``size`` bytes from a ``fp``, aligned to
    ``bs`` bytes blocks.

    Example:

    file contents (hex): 00 11 22 33 44 55 66 77
    size: 3
    bs: 4
    will return: 00 11 22
    ..then read and discard one byte to align to the
    next 4-bytes block.

    :param fp: file object from which to read
    :param size: size to read
    :param bs: size of a "read block"
    """

    data = fp.read(size)
    _padding = (bs - size % bs) % bs
    if _padding > 0:
        fp.read(_padding)
    return data


def aligned_write(fp, data, bs=4):
    """
    Write data and align to the next bs-sized block.

    :param fp: file object from which to read
    :param data: data to write
    :param bs: size of a file block
    """
    _padding = (bs - len(data) % bs) % bs
    if _padding > 0:
        fp.read(_padding)
    fp.write(data)
    fp.write('\x00' * _padding)
