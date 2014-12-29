#!/usr/bin/env python

from __future__ import print_function, division

import logging
import sys
from collections import Counter

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket


logger = logging.getLogger('pcapng')
logger.setLevel(logging.INFO)  # Debug will slow things down a lot!

handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter(
    '\033[1;37;40m  %(levelname)s  \033[0m \033[0;32m%(message)s\033[0m')
handler.setFormatter(formatter)
logger.addHandler(handler)


def title(text):
    print(u'-' * 60)
    print(u'\033[1m{0}\033[0m'.format(text))
    print(u'-' * 60)


def human_number(num, k=1000):
    powers = [''] + list('kMGTPEY')
    assert isinstance(num, (int, long))
    for i, suffix in enumerate(powers):
        if (num < (k ** (i + 1))) or (i == len(powers) - 1):
            return '{0:d}{1}'.format(int(round(num / (k ** i))), suffix)
    raise AssertionError('Should never reach this')


if __name__ == '__main__':
    import sys
    rdr = FileScanner(sys.stdin)

    ip_src_count = Counter()
    ip_dst_count = Counter()
    ip_src_size = Counter()
    ip_dst_size = Counter()

    tcp_src_count = Counter()
    tcp_dst_count = Counter()
    tcp_src_size = Counter()
    tcp_dst_size = Counter()

    for block in rdr:
        # print(repr(block))

        if isinstance(block, EnhancedPacket):
            assert block.interface.link_type == 1  # must be ethernet!

            decoded = Ether(block.packet_data)
            # print(repr(Ether(block.packet_data))[:400] + '...')

            _pl1 = decoded.payload
            if isinstance(_pl1, IP):
                ip_src_count[_pl1.src] += 1
                ip_dst_count[_pl1.dst] += 1
                ip_src_size[_pl1.src] += block.packet_len
                ip_dst_size[_pl1.dst] += block.packet_len

                _pl2 = _pl1.payload
                if isinstance(_pl2, TCP):
                    _src = '{0}:{1}'.format(_pl1.dst, _pl2.dport)
                    _dst = '{0}:{1}'.format(_pl1.src, _pl2.sport)
                    tcp_src_count[_src] += 1
                    tcp_dst_count[_dst] += 1
                    tcp_src_size[_src] += block.packet_len
                    tcp_dst_size[_dst] += block.packet_len

    # Print report
    # ------------------------------------------------------------

    # def _rsic(o):
    #     return sorted(o.iteritems(), key=lambda x: x[1], reverse=True)

    _rsic = lambda o: sorted(o.iteritems(), key=lambda x: x[1], reverse=True)

    title('IP Sources (by packet count)')
    for key, val in _rsic(ip_src_count)[:30]:
        print("\033[1m{1:>5s}\033[0m {0}".format(key, human_number(val)))
    print()

    title('IP Sources (by total size)')
    for key, val in _rsic(ip_src_size)[:30]:
        print("\033[1m{1:>5s}B\033[0m {0}".format(key, human_number(val, k=1024)))
    print()

    title('IP Destinations (by packet count)')
    for key, val in _rsic(ip_dst_count)[:30]:
        print("\033[1m{1:>5s}\033[0m {0}".format(key, human_number(val)))
    print()

    title('IP Destinations (by total size)')
    for key, val in _rsic(ip_dst_size)[:30]:
        print("\033[1m{1:>5s}B\033[0m {0}".format(key, human_number(val, k=1024)))
    print()

    title('TCP Sources (by packet count)')
    for key, val in _rsic(tcp_src_count)[:30]:
        print("\033[1m{1:>5s}\033[0m {0}".format(key, human_number(val)))
    print()

    title('TCP Sources (by total size)')
    for key, val in _rsic(tcp_src_size)[:30]:
        print("\033[1m{1:>5s}B\033[0m {0}".format(key, human_number(val, k=1024)))
    print()

    title('TCP Destinations (by packet count)')
    for key, val in _rsic(tcp_dst_count)[:30]:
        print("\033[1m{1:>5s}\033[0m {0}".format(key, human_number(val)))
    print()

    title('TCP Destinations (by total size)')
    for key, val in _rsic(tcp_dst_size)[:30]:
        print("\033[1m{1:>5s}B\033[0m {0}".format(key, human_number(val, k=1024)))
    print()
