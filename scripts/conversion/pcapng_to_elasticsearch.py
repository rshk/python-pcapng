"""
Convert a pcap-ng file to a format suitable for bulk insert
in elasticsearch.

Example:

./pcapng_to_elasticsearch.py < capture.pcapng > capture.json
curl -XPUT localhost:9200/net-traffic/_bulk --data-binary @capture.json
"""

from __future__ import print_function, division

import logging
import sys
import json

from scapy.layers.l2 import Ether
from scapy.packet import Raw

from pcapng import PcapngReader
from pcapng.objects import EnhancedPacket


pcapng_logger = logging.getLogger('pcapng')
pcapng_logger.setLevel(logging.INFO)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter(
    '\033[1;37;40m  %(levelname)s  \033[0m \033[0;32m%(message)s\033[0m')
handler.setFormatter(formatter)

pcapng_logger.addHandler(handler)
logger.addHandler(handler)


if __name__ == '__main__':
    import sys
    rdr = PcapngReader(sys.stdin)

    # counters = defaultdict(Counter)
    packet_id = 0

    def _find_layers(pkt):
        # Iterating pkt is quite a confused thing..
        # Another options would be getting layers as pkt[id]
        while True:
            yield pkt
            if not pkt.payload:
                return
            pkt = pkt.payload

    for block in rdr:
        # print(repr(block))

        if isinstance(block, EnhancedPacket):
            # We expect only ethernet packets in this dump
            assert block._interface.link_type == 1

            packet = Ether(block.packet_data)  # Decode packet data
            packet_id += 1  # We only count packets!

            logger.info("Processing packet {0}: {1}"
                        .format(packet_id, repr(packet)[:200]))

            packet_record = {
                '@timestamp': block.timestamp,
                'packet_size': block.packet_len,
                # todo: add information about interface, etc?
            }

            for pkt in _find_layers(packet):
                if isinstance(pkt, Raw):
                    # Ignore raw packet contents!
                    continue
                packet_record[pkt.name] = pkt.fields

            print(json.dumps({'index': {
                '_type': 'packet-' + pkt.name,
                '_id': packet_id}}))
            print(json.dumps(packet_record))
