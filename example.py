import logging
import sys

from pcapng import PCAPNG_Reader


logger = logging.getLogger('pcapng')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter(
    '\033[1;37;40m  %(levelname)s  \033[0m \033[0;32m%(message)s\033[0m')
handler.setFormatter(formatter)
logger.addHandler(handler)


if __name__ == '__main__':
    import sys
    rdr = PCAPNG_Reader(sys.stdin)
    for packet in rdr:
        print(repr(packet))
    # while True:
    #     packet = rdr.read_block()
    #     print(repr(packet))
