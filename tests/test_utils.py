from pcapng.utils import (
    unpack_ipv4, unpack_ipv6, unpack_macaddr, unpack_euiaddr)


def test_unpack_ipv4():
    assert unpack_ipv4('\x00\x00\x00\x00') == '0.0.0.0'
    assert unpack_ipv4('\xff\xff\xff\xff') == '255.255.255.255'
    assert unpack_ipv4('\x0a\x10\x20\x30') == '10.16.32.48'


def test_unpack_ipv6():
    assert unpack_ipv6('\x00\x11\x22\x33\x44\x55\x66\x77'
                       '\x88\x99\xaa\xbb\xcc\xdd\xee\xff') \
        == '0011:2233:4455:6677:8899:aabb:ccdd:eeff'


def test_unpack_macaddr():
    assert unpack_macaddr('\x00\x11\x22\xaa\xbb\xcc') == \
        '00:11:22:aa:bb:cc'


def test_unpack_euiaddr():
    assert unpack_euiaddr('\x00\x11\x22\x33\xaa\xbb\xcc\xdd') == \
        '00:11:22:33:aa:bb:cc:dd'
