from collections import Mapping
import io
import struct

from pcapng.exceptions import (
    BadMagic, StreamEmpty, CorruptedFile, TruncatedFile)


SECTION_HEADER_MAGIC = 0x0a0d0d0a
BYTE_ORDER_MAGIC = 0x1a2b3c4d
BYTE_ORDER_MAGIC_INVERSE = 0x4d3c2b1a

# Anything greater and we cannot safely read
# todo: add support for this!
CURRENT_SUPPORTED_VERSION = (1, 0)


INT_FORMATS = {16: 'h', 32: 'i', 64: 'q'}


def read_int(stream, size, signed=False, endianness='>'):
    fmt = INT_FORMATS.get(size)
    fmt = fmt.lower() if signed else fmt.upper()
    assert endianness in '<>!='
    fmt = endianness + fmt
    size_bytes = size // 8
    data = read_bytes(stream, size_bytes)
    return struct.unpack(fmt, data)[0]


def read_section_header(stream):
    """
    Read a section header from a stream.

    :returns: a dict containing information about the section
    """

    blktype = read_int(stream, 32, '>')

    if blktype != SECTION_HEADER_MAGIC:
        raise BadMagic(
            'Invalid magic number: got 0x{0:08X}, expected 0x{1:08X}'
            .format(blktype, SECTION_HEADER_MAGIC))

    blk_len_raw = read_bytes(stream, 4)  # We don't know endianness yet..
    byte_order_magic = read_int(stream, 32, '>')  # Default BIG
    if byte_order_magic == BYTE_ORDER_MAGIC:
        endianness = '>'  # BIG
    else:
        if byte_order_magic != BYTE_ORDER_MAGIC_INVERSE:
            raise BadMagic('Wrong byte order magic: got 0x{0:08X}, expected '
                           '0x{1:08X} or 0x{2:08X}'
                           .format(byte_order_magic, BYTE_ORDER_MAGIC,
                                   BYTE_ORDER_MAGIC_INVERSE))
        endianness = '<'  # LITTLE

    blk_len = struct.unpack(endianness + 'I', blk_len_raw)[0]

    v_maj = read_int(stream, 16, False, endianness)
    v_min = read_int(stream, 16, False, endianness)
    section_len = read_int(stream, 64, True, endianness)
    options_len = blk_len - (7 * 4)
    options_raw = read_bytes(stream, options_len)
    blk_len2 = read_int(stream, 32, False, endianness)

    if blk_len != blk_len2:
        raise CorruptedFile('Mismatching block lengths: {0} and {1}'
                            .format(blk_len, blk_len2))

    return {
        'endianness': endianness,
        'block_length': blk_len,  # Not realy needed..
        'version': (v_maj, v_min),
        'section_length': section_len,
        'options_raw': options_raw,
    }


def read_block_data(stream, endianness):
    """
    Read block data from a stream.
    """

    block_length = read_int(stream, 32, signed=False, endianness=endianness)
    payload_length = block_length - 12  # bytes
    block_data = read_bytes_padded(stream, payload_length)
    block_length2 = read_int(stream, 32, signed=False, endianness=endianness)
    if block_length != block_length2:
        raise CorruptedFile('Mismatching block lengths: {0} and {1}'
                            .format(block_length, block_length2))
    return block_data


def read_bytes(stream, size):
    """
    Read the given amount of raw bytes from a stream.

    :raises: StreamEmpty if zero bytes were read
    :raises: TruncatedFile if 0 < bytes < size were read
    """

    if size == 0:
        return ''

    try:
        data = stream.read(size)
    except EOFError:
        raise StreamEmpty('Got EOFError while reading from stream')
    if len(data) == 0:
        raise StreamEmpty('Zero bytes read from stream')
    if len(data) < size:
        raise TruncatedFile('Trying to read {0} bytes, only got {1}'
                            .format(size, len(data)))
    return data


def read_bytes_padded(stream, size, pad_block_size=4):
    """
    Read the given amount of bytes from a stream, plus read and discard
    any necessary extra byte to align up to the pad_block_size-sized
    next block.
    """

    if stream.tell() % pad_block_size != 0:
        raise RuntimeError('Stream is misaligned!')

    data = read_bytes(stream, size)
    padding = (pad_block_size - (size % pad_block_size)) % pad_block_size
    if padding > 0:
        read_bytes(stream, padding)
    return data


class StructField(object):
    # def __init__(self):
    #     pass

    def load(self, stream, endianness):
        raise NotImplementedError


class RawBytes(StructField):
    def __init__(self, size):
        self.size = size  # in bytes!

    def load(self, stream, endianness):
        return read_bytes(stream, self.size)


class IntField(StructField):
    def __init__(self, size, signed=False):
        self.size = size  # in bits!
        self.signed = signed

    def load(self, stream, endianness):
        number = read_int(stream, self.size, signed=self.signed,
                          endianness=endianness)
        return number


class OptionsField(StructField):
    def __init__(self, options_schema):
        self.options_schema = options_schema

    def load(self, stream, endianness):
        options = read_options(stream, endianness)
        return Options(self.options_schema, options)


class PacketDataField(StructField):
    def load(self, stream, endianness):
        captured_len = read_int(stream, 32, False, endianness)
        packet_len = read_int(stream, 32, False, endianness)
        packet_data = read_bytes_padded(stream, packet_len)
        return captured_len, packet_len, packet_data


class SimplePacketDataField(StructField):
    def load(self, stream, endianness):
        packet_len = read_int(stream, 32, False, endianness)
        packet_data = read_bytes_padded(stream, packet_len)
        return packet_len, packet_data


class ListField(StructField):
    def __init__(self, subfield):
        self.subfield = subfield

    def load(self, stream, endianness):
        return list(self._iter_load())

    def _iter_load(self, stream, endianness):
        while True:
            try:
                yield self.subfield.load(stream)
            except StreamEmpty:
                return


class NameResolutionRecordField(StructField):
    def load(self, stream, endianness):
        record_type = read_int(stream, 16, False, endianness)
        record_length = read_int(stream, 16, False, endianness)

        if record_type == 0:
            raise StreamEmpty('End marker reached')

        data = read_bytes_padded(stream, record_length)

        if record_type == 1:  # IPv4
            return {'address': data[:4], 'name': data[4:]}

        if record_type == 2:  # IPv6
            return {'address': data[:16], 'name': data[16:]}

        return {'raw': data}


def read_options(stream, endianness):
    """
    Read "options" from an "options block" in a stream,
    up to an empty stream, or an end marker.
    """

    def _iter_read_options(stream, endianness):
        while True:
            try:
                option_code = read_int(stream, 16, None, endianness)
                option_length = read_int(stream, 16, None, endianness)

                if option_code == 0:  # End of options
                    return

                payload = read_bytes_padded(option_length)
                yield option_code, payload

            except StreamEmpty:
                return

    return list(_iter_read_options(stream, endianness))


class Options(Mapping):
    def __init__(self, schema, data=None):
        self._schema = {}
        self._field_names = {}
        self._update_schema([
            (0, 'opt_endofopt'),
            (1, 'opt_comment', lambda x: unicode(x, encoding='utf-8')),
        ])
        self._update_schema(schema)

    def _update_schema(self, schema):
        for item in schema:
            if len(item) == 2:
                code, name = item
                constructor = lambda x: x
            elif len(item) == 3:
                code, name, constructor = item
            else:
                raise TypeError('Options schema item must be a 2- or 3-tuple')
            self._schema[code] = {
                'name': name,
                'constructor': constructor,
            }
            self._field_names[name] = 'code'

    def _set_data(self, data):
        if data is not None:
            for key, val in data:
                if key not in self._data:
                    self._data[key] = []
                val = self._get_constructor(key)(val)
                self._data[key].append(val)

    def _get_constructor(self, code):
        _schema = self._schema.get(code) or {}
        return _schema.get('constructor') or (lambda x: x)

    def __getitem__(self, name):
        pass


def struct_decode(schema, stream, endianness='='):
    decoded = {}
    for name, field in schema:
        decoded[name] = field.load(stream, endianness=endianness)
    return decoded


def struct_encode(schema, obj, outstream, endianness='='):
    raise NotImplementedError


def struct_decode_string(schema, data):
    return struct_decode(schema, io.BytesIO())


def struct_encode_string(schema, obj):
    outstream = io.BytesIO()
    struct_encode(schema, obj, outstream)
    return outstream.getvalue()
