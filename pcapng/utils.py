import io
import socket


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
    return ':'.join(format(ord(x), '02x') for x in _get_pairs(data))


def unpack_macaddr(data):
    return ':'.join(format(ord(x), '02x') for x in data)


def unpack_euiaddr(data):
    return unpack_macaddr(data)
