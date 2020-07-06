"""
Convert a pcap-ng file to a format suitable for bulk insert
in elasticsearch.

Example:


curl -XPUT localhost:9200/net-traffic -d '{"packet": {
    "properties": {
        "@tymestamp": {"type": "date"}
    },
    "dynamic_templates": [{
        "packet_fields_as_string": {
            "path_match": "*.*",
            "mapping": {
                "type": "string",
                "index": "not_analyzed"
            }
        }
    }]
}}'

./pcapng_to_elasticsearch.py < capture.pcapng > capture.json

curl -XPUT localhost:9200/net-traffic/_bulk --data-binary @capture.json
"""

from __future__ import division, print_function

import hashlib
import json
import logging
import sys

from scapy.layers.all import *  # Needed for decode!  # noqa
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from pcapng import PcapngReader
from pcapng.objects import EnhancedPacket


class SaferJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            return json.JSONEncoder.default(self, obj)
        except TypeError:
            return repr(obj)


pcapng_logger = logging.getLogger("pcapng")
pcapng_logger.setLevel(logging.INFO)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter(
    "\033[1;37;40m  %(levelname)s  \033[0m \033[0;32m%(message)s\033[0m"
)
handler.setFormatter(formatter)

pcapng_logger.addHandler(handler)
logger.addHandler(handler)


if __name__ == "__main__":
    import sys

    rdr = PcapngReader(sys.stdin)

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

            # We need to figure out a unique id for this packet,
            # in a deterministic way (in case we re-import the
            # same batch..)
            # Hopefully, this will be unique..
            packet_id = hashlib.sha1(
                str(block.timestamp) + block.packet_data
            ).hexdigest()

            packet = Ether(block.packet_data)  # Decode packet data

            logger.info(
                "Processing packet {0}: {1}".format(packet_id, repr(packet)[:200])
            )

            packet_record = {
                "@timestamp": block.timestamp * 1000,  # in milliseconds
                "packet_size": block.packet_len,
                # todo: add information about interface, etc?
            }

            for pkt in _find_layers(packet):
                if isinstance(pkt, Raw):
                    # Ignore raw packet contents!
                    continue
                packet_record[pkt.name] = pkt.fields

            try:
                _pkt_json = json.dumps(packet_record, cls=SaferJsonEncoder)

            except Exception:
                logger.exception("Unable to serialize json packet")

            else:
                print(json.dumps({"index": {"_type": "packet", "_id": packet_id}}))
                print(_pkt_json)
