#!/usr/bin/env python

from __future__ import print_function

import sys
import io
from datetime import datetime
import binascii

import pcapng
from pcapng.blocks import SectionHeader, InterfaceDescription, EnhancedPacket


def col256(text, fg=None, bg=None, bold=False):
    def _get_color(col):
        return u'8;5;{0:d}'.format(_to_color(col))

    def _to_color(num):
        if isinstance(num, (int, long)):
            return num  # Assume it is already a color

        if isinstance(num, basestring) and len(num) <= 3:
            return 16 + int(num, 6)

        raise ValueError("Invalid color: {0!r}".format(num))

    if not isinstance(text, unicode):
        text = unicode(text, encoding='utf-8')

    buf = io.StringIO()

    if bold:
        buf.write(u'\x1b[1m')

    if fg is not None:
        buf.write(u'\x1b[3{0}m'.format(_get_color(fg)))

    if bg is not None:
        buf.write(u'\x1b[4{0}m'.format(_get_color(bg)))

    buf.write(text)
    buf.write(u'\x1b[0m')
    return buf.getvalue()


def dump_information(scanner):
    for block in scanner:
        if isinstance(block, SectionHeader):
            pprint_sectionheader(block)
        elif isinstance(block, InterfaceDescription):
            pprint_interfacedesc(block)
        elif isinstance(block, EnhancedPacket):
            pprint_enhanced_packet(block)
        else:
            print('    ' + str(block))


def pprint_options(options):
    if len(options):
        yield '--'
        for key, values in options.iter_all_items():
            for value in values:
                yield col256(key + ':', bold=True, fg='453')
                yield col256(unicode(value), fg='340')


def pprint_sectionheader(block):
    endianness_desc = {
        '<': 'Little endian',
        '>': 'Big endian',
        '!': 'Network (Big endian)',
        '=': 'Native',
    }

    text = [
        col256(' Section ', bg='400', fg='550'),
        col256('version:', bold=True),
        col256('.'.join(str(x) for x in block.version), fg='145'),

        # col256('endianness:', bold=True),
        '-',
        col256(endianness_desc.get(block.endianness, 'Unknown endianness'),
               bold=True),
        '-',
    ]

    if block.length < 0:
        text.append(col256('unspecified size', bold=True))
    else:
        text.append(col256('length:', bold=True))
        text.append(col256(str(block.length), fg='145'))

    text.extend(pprint_options(block.options))
    print(' '.join(text))


def pprint_interfacedesc(block):
    text = [
        '   ',
        col256(' Interface #{0} '.format(block.interface_id),
               bg='010', fg='453'),
        col256('Link type:', bold=True),
        col256(unicode(block.link_type), fg='140'),
        col256(block.link_type_description, fg='145'),
        col256('Snap length:', bold=True),
        col256(unicode(block.snaplen), fg='145'),
    ]
    text.extend(pprint_options(block.options))
    print(' '.join(text))


def pprint_enhanced_packet(block):
    text = [
        '   ',
        col256(' Packet+ ', bg='001', fg='345'),

        # col256('NIC:', bold=True),
        # col256(unicode(block.interface_id), fg='145'),
        col256(unicode(block.interface.options['if_name']), fg='140'),

        col256(unicode(datetime.utcfromtimestamp(block.timestamp)
                       .strftime('%Y-%m-%d %H:%M:%S')), fg='455'),
    ]

    text.extend([
        # col256('Size:', bold=True),
        col256(unicode(block.packet_len) + u' bytes', fg='025'),
    ])
    if block.captured_len != block.packet_len:
        text.extend([
            col256('Truncated to:', bold=True),
            col256(unicode(block.captured_len) + u'bytes', fg='145'),
        ])

    text.extend(pprint_options(block.options))
    print(' '.join(text))
    # print('\n'.join('        ' + line
    #                 for line in format_binary_data(block.packet_data)))


def format_binary_data(data):
    stream = io.BytesIO(data)
    row_offset = 0
    row_size = 16  # bytes

    while True:
        data = stream.read(row_size)
        if not data:
            return

        hexrow = io.BytesIO()
        asciirow = io.BytesIO()
        for i, byte in enumerate(data):
            if 32 <= ord(byte) <= 126:
                asciirow.write(byte)
            else:
                asciirow.write('.')
            hexrow.write(format(ord(byte), '02x'))
            if i < 15:
                if i % 2 == 1:
                    hexrow.write(' ')
                if i % 8 == 7:
                    hexrow.write(' ')

            row_offset += 1

        yield '{0:08x}:   {1:40s}   {2:16s}'.format(
            row_offset,
            hexrow.getvalue(),
            asciirow.getvalue())


def main():
    if (len(sys.argv) > 1) and (sys.argv[1] != '-'):
        with open(sys.argv[1], 'rb') as fp:
            scanner = pcapng.FileScanner(fp)
            dump_information(scanner)
    else:
        scanner = pcapng.FileScanner(sys.stdin)
        dump_information(scanner)


if __name__ == '__main__':
    main()
