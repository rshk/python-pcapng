from collections import Mapping
import abc
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


INT_FORMATS = {8: 'b', 16: 'h', 32: 'i', 64: 'q'}


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

    .. note::
        The byte order magic will be removed from the returned data
        This is ok as we don't need it anymore once we determined
        the correct endianness of the section.

    :returns: a dict containing the 'endianness' and 'data' keys
    """

    # Read the length as raw bytes, then keep for later (since we
    # don't know the section endianness yet, we cannot parse this)
    blk_len_raw = read_bytes(stream, 4)

    # Read the "byte order magic" and see which endianness reports
    # it correctly (should be 0x1a2b3c4d)
    byte_order_magic = read_int(stream, 32, '>')  # Default BIG
    if byte_order_magic == BYTE_ORDER_MAGIC:
        endianness = '>'  # BIG
    else:
        if byte_order_magic != BYTE_ORDER_MAGIC_INVERSE:
            # We got an invalid number..
            raise BadMagic('Wrong byte order magic: got 0x{0:08X}, expected '
                           '0x{1:08X} or 0x{2:08X}'
                           .format(byte_order_magic, BYTE_ORDER_MAGIC,
                                   BYTE_ORDER_MAGIC_INVERSE))
        endianness = '<'  # LITTLE

    # Now we can safely decode the block length from the bytes we read earlier
    blk_len = struct.unpack(endianness + 'I', blk_len_raw)[0]

    # ..and we then just want to read the appropriate amount of raw data.
    # Exclude: magic, len, bom, len (16 bytes)
    payload_size = blk_len - (4 + 4 + 4 + 4)
    block_data = read_bytes_padded(stream, payload_size)

    # Double-check lenght at block end
    blk_len2 = read_int(stream, 32, False, endianness)
    if blk_len != blk_len2:
        raise CorruptedFile('Mismatching block lengths: {0} and {1}'
                            .format(blk_len, blk_len2))

    return {
        'endianness': endianness,
        'data': block_data,
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

    data = stream.read(size)
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
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def load(self, stream, endianness):
        pass


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
        return Options(schema=self.options_schema, data=options,
                       endianness=endianness)


class PacketDataField(StructField):
    def load(self, stream, endianness):
        captured_len = read_int(stream, 32, False, endianness)
        packet_len = read_int(stream, 32, False, endianness)
        packet_data = read_bytes_padded(stream, captured_len)
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
        return list(self._iter_load(stream, endianness))

    def _iter_load(self, stream, endianness):
        while True:
            try:
                yield self.subfield.load(stream, endianness)
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
            return {
                'type': record_type,
                'address': data[:4],
                'name': data[4:],
            }

        if record_type == 2:  # IPv6
            return {
                'type': record_type,
                'address': data[:16],
                'name': data[16:],
            }

        return {'type': record_type, 'raw': data}


def read_options(stream, endianness):
    """
    Read "options" from an "options block" in a stream,
    up to an empty stream, or an end marker.
    """

    def _iter_read_options(stream, endianness):
        while True:
            try:
                option_code = read_int(stream, 16, False, endianness)
                option_length = read_int(stream, 16, False, endianness)

                if option_code == 0:  # End of options
                    return

                payload = read_bytes_padded(stream, option_length)
                yield option_code, payload

            except StreamEmpty:
                return

    return list(_iter_read_options(stream, endianness))


class Options(Mapping):
    """
    Wrapper for the contents of the "options" field.

    This class will map names on numeric fields and perform all the
    necessary transformations on the data before returning.
    """

    def __init__(self, schema, data, endianness):
        self.schema = {}  # Schema of option fields: {<code>: {..def..}}
        self._field_names = {}  # Map names to codes
        self.raw_data = {}  # List of (code, value) tuples
        self.endianness = endianness  # one of '<>!='

        # This is the default schema, common to all objects
        self._update_schema([
            (0, 'opt_endofopt'),
            (1, 'opt_comment', 'string'),
        ])
        self._update_schema(schema)

        # Update raw data with current values
        self._update_data(data)

    # -------------------- Nice interface :) --------------------

    def __getitem__(self, name):
        return self._get_converted(name)

    def __len__(self):
        return len(self.raw_data)

    def __iter__(self):
        for key in self.raw_data:
            yield self._get_name_alias(key)

    def get_all(self, name):
        return self._get_all_converted(name)

    def get_raw(self, name):
        return self._get_raw(name)

    def get_all_raw(self, name):
        return self._get_all_raw(name)

    def iter_all_items(self):
        for key in self:
            yield key, self.get_all(key)

    # -------------------- Internal methods --------------------

    def _update_schema(self, schema):
        for item in schema:
            if len(item) == 2:
                code, name = item
                ftype = None

            elif len(item) == 3:
                code, name, ftype = item

            else:
                raise TypeError('Options schema item must be a 2- or 3-tuple')

            self.schema[code] = {'name': name, 'ftype': ftype}
            self._field_names[name] = code

    def _update_data(self, data):
        if data is None:
            return

        for code, value in data:
            if code not in self.raw_data:
                self.raw_data[code] = []
            self.raw_data[code].append(value)

    def _resolve_name(self, name):
        return self._field_names.get(name) or name

    def _get_name_alias(self, code):
        if code in self.schema:
            return self.schema[code]['name']
        return code

    def _get_raw(self, name):
        name = self._resolve_name(name)
        return self.raw_data[name][0]

    def _get_all_raw(self, name):
        name = self._resolve_name(name)
        return list(self.raw_data[name])

    def _get_converted(self, name):
        value = self._get_raw(name)
        return self._convert(name, value)

    def _get_all_converted(self, name):
        value = self._get_all_raw(name)
        return self._convert_all(name, value)

    def _convert(self, code, value):
        code = self._resolve_name(code)
        if code in self.schema:
            return self._convert_value(value, self.schema[code]['ftype'])
        return value

    def _convert_all(self, code, values):
        code = self._resolve_name(code)
        if code in self.schema:
            return [self._convert_value(value, self.schema[code]['ftype'])
                    for value in values]
        return values

    def _convert_value(self, value, ftype):
        if ftype is None:
            return value

        if hasattr(ftype, '__call__'):
            return ftype(value, self.endianness)

        if ftype in ('str', 'string', 'unicode'):
            return unicode(value, encoding='utf-8')

        _numeric_types = {
            'u8': 'B', 'i8': 'b',
            'u16': 'H', 'i16': 'h',
            'u32': 'I', 'i32': 'i',
            'u64': 'Q', 'i64': 'q',
        }
        if ftype in _numeric_types:
            return struct.unpack(
                self.endianness + _numeric_types[ftype], value)[0]

        raise ValueError('Unsupported field type: {0}'.format(ftype))


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
