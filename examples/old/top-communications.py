"""
Find communications using the most traffic
"""

from __future__ import print_function

import logging
import sys
from collections import Counter, defaultdict

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from pcapng import PcapngReader
from pcapng.objects import EnhancedPacket

logger = logging.getLogger("pcapng")
logger.setLevel(logging.INFO)  # Debug will slow things down a lot!

handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter(
    "\033[1;37;40m  %(levelname)s  \033[0m \033[0;32m%(message)s\033[0m"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


if __name__ == "__main__":
    import sys

    rdr = PcapngReader(sys.stdin)

    counters = defaultdict(Counter)

    for block in rdr:
        # print(repr(block))

        if isinstance(block, EnhancedPacket):
            # We expect only ethernet packets in this dump
            assert block._interface.link_type == 1

            packet = Ether(block.packet_data)
            # print(repr(Ether(block.packet_data))[:400] + '...')
            _pksize = block.packet_len

            if IP in packet:

                if TCP in packet:
                    # TCP packet
                    _tcp_com = (
                        packet[IP].src,
                        packet[TCP].sport,
                        packet[IP].dst,
                        packet[TCP].dport,
                    )
                    counters["TCP Communications (count)"][_tcp_com] += 1
                    counters["TCP Communications (size)"][_tcp_com] += _pksize

                elif UDP in packet:
                    # UDP packet
                    _udp_com = (
                        packet[IP].src,
                        packet[UDP].sport,
                        packet[IP].dst,
                        packet[UDP].dport,
                    )
                    counters["UDP Communications (count)"][_udp_com] += 1
                    counters["UDP Communications (size)"][_udp_com] += _pksize

                else:
                    # Generic IP packet
                    _ip_com = (packet[IP].src, packet[IP].dst)
                    counters["Other IP Communications (count)"][_ip_com] += 1
                    counters["Other IP Communications (size)"][
                        _ip_com
                    ] += _pksize  # noqa

            else:
                counters["Non-IP packets (size)"]["total"] += _pksize
                counters["Non-IP packets (count)"]["total"] += 1

    # Print report
    # ------------------------------------------------------------

    for counter_name, items in sorted(counters.iteritems()):
        print(counter_name)
        print("-" * 60)
        sorted_items = sorted(items.iteritems(), key=lambda x: x[1], reverse=True)

        for key, value in sorted_items[:30]:
            print("{1:15d} {0}".format(key, value))

        print()
