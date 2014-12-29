import io
import socket
import struct


def unpack_ipv4(data):
    return socket.inet_ntoa(data)


def _get_pairs(data):
    stream = io.BytesIO(data)
    while True:
        b = stream.read(2)
        if not b:
            return
        yield b


def unpack_ipv6(data):
    return ':'.join(
        '{0:02x}{1:02x}'.format(ord(x), ord(y))
        for (x, y) in _get_pairs(data))


def unpack_macaddr(data):
    return ':'.join(format(ord(x), '02x') for x in data)


def unpack_euiaddr(data):
    return unpack_macaddr(data)


def unpack_timestamp_resolution(data):
    """
    Unpack a timestamp resolution.

    Returns a floating point number representing the timestamp
    resolution (multiplier).
    """
    if len(data) != 1:
        raise ValueError('Data must be exactly one byte')
    num = ord(data)
    base = 2 if (num >> 7 & 1) else 10
    exponent = num & 0b01111111
    return base ** (-exponent)


def pack_timestamp_resolution(base, exponent):
    """
    Pack a timestamp resolution.

    :param base: 2 or 10
    :param exponent: negative power of the base to be encoded
    """
    exponent = abs(exponent)
    if base == 2:
        return struct.pack('B', exponent | 0b10000000)
    if base == 10:
        return struct.pack('B', exponent)
    raise ValueError('Supported bases are: 2, 10')
