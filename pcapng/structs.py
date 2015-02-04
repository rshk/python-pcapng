"""
Module providing facilities for handling struct-like data.
"""

from collections import Mapping
import abc
import io
import struct

from pcapng.utils import (
    unpack_ipv4, unpack_ipv6, unpack_macaddr, unpack_euiaddr)
from pcapng.exceptions import (
    BadMagic, StreamEmpty, CorruptedFile, TruncatedFile)


SECTION_HEADER_MAGIC = 0x0a0d0d0a
BYTE_ORDER_MAGIC = 0x1a2b3c4d
BYTE_ORDER_MAGIC_INVERSE = 0x4d3c2b1a

# Anything greater and we cannot safely read
# todo: add support for this!
CURRENT_SUPPORTED_VERSION = (1, 0)


INT_FORMATS = {8: 'b', 16: 'h', 32: 'i', 64: 'q'}


def read_int(stream, size, signed=False, endianness='='):
    """
    Read (and decode) an integer number from a binary stream.

    :param stream: an object providing a ``read()`` method
    :param size: the size, in bits, of the number to be read.
        Supported sizes are: 8, 16, 32 and 64 bits.
    :param signed: Whether a signed or unsigned number is required.
        Defaults to ``False`` (unsigned int).
    :param endianness: specify the endianness to use to decode the number,
        in the same format used by Python :py:mod:`struct` module.
        Defaults to '=' (native endianness). '!' means "network" endianness
        (big endian), '<' little endian, '>' big endian.
    :return: the read integer number
    """
    fmt = INT_FORMATS.get(size)
    fmt = fmt.lower() if signed else fmt.upper()
    assert endianness in '<>!='
    fmt = endianness + fmt
    size_bytes = size // 8
    data = read_bytes(stream, size_bytes)
    return struct.unpack(fmt, data)[0]


def read_section_header(stream):
    """
    Read a section header block from a stream.

    .. note::
        The byte order magic will be removed from the returned data
        This is ok as we don't need it anymore once we determined
        the correct endianness of the section.

    :returns: a dict containing the ``'endianness'`` and ``'data'`` keys
        that will be used to construct a :py:mod:`~pcapng.blocks.SectionHeader`
        instance.
    """

    # Read the length as raw bytes, then keep for later (since we
    # don't know the section endianness yet, we cannot parse this)
    blk_len_raw = read_bytes(stream, 4)

    # Read the "byte order magic" and see which endianness reports
    # it correctly (should be 0x1a2b3c4d)
    byte_order_magic = read_int(stream, 32, False, '>')  # Default BIG
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

    Each "block" is in the form:

    - 32bit integer indicating the size (including header and size)
    - block payload (the above-specified number of bytes minus 12)
    - 32bit integer indicating the size (again)

    :param stream: the stream from which to read data
    :param endianness: Endianness marker, one of '<', '>', '!', '='.
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

    :param stream: the stream from which to read data
    :param size: the size to read, in bytes
    :returns: the read data
    :raises: :py:exc:`~pcapng.exceptions.StreamEmpty` if zero bytes were read
    :raises: :py:exc:`~pcapng.exceptions.TruncatedFile` if 0 < bytes < size
        were read
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

    :param stream: the stream from which to read data
    :param size: the size to read, in bytes
    :returns: the read data
    :raises: :py:exc:`~pcapng.exceptions.StreamEmpty` if zero bytes were read
    :raises: :py:exc:`~pcapng.exceptions.TruncatedFile` if 0 < bytes < size
        were read
    """

    if stream.tell() % pad_block_size != 0:
        raise RuntimeError('Stream is misaligned!')

    data = read_bytes(stream, size)
    padding = (pad_block_size - (size % pad_block_size)) % pad_block_size
    if padding > 0:
        read_bytes(stream, padding)
    return data


class StructField(object):
    """Abstract base class for struct fields"""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def load(self, stream, endianness):
        pass

    def __repr__(self):
        return '{0}()'.format(self.__class__.__name__)

    def __unicode__(self):
        return self.__repr__().encode('UTF-8')


class RawBytes(StructField):
    """
    Field containing a fixed-width amount of raw bytes

    :param size: field size, in bytes
    """

    def __init__(self, size):
        self.size = size  # in bytes!

    def load(self, stream, endianness):
        return read_bytes(stream, self.size)

    def __repr__(self):
        return ('{0}(size={1!r})'.format(self.__class__.__name__, self.size))


class IntField(StructField):
    """
    Field containing an integer number.

    :param size: number size, in bits. Currently supported
        are 8, 16, 32 and 64-bit integers
    :param signed: whether the number is a signed or unsigned
        integer. Defaults to False (unsigned)
    """

    def __init__(self, size, signed=False):
        self.size = size  # in bits!
        self.signed = signed

    def load(self, stream, endianness):
        number = read_int(stream, self.size, signed=self.signed,
                          endianness=endianness)
        return number

    def __repr__(self):
        return ('{0}(size={1!r}, signed={2!r})'
                .format(self.__class__.__name__, self.size, self.signed))


class OptionsField(StructField):
    """
    Field containing some options.

    :param options_schema:
        Same as the ``schema`` parameter to :py:class:`Options` class
        constructor.
    """

    def __init__(self, options_schema):
        self.options_schema = options_schema

    def load(self, stream, endianness):
        options = read_options(stream, endianness)
        return Options(schema=self.options_schema, data=options,
                       endianness=endianness)

    def __repr__(self):
        return ('{0}({1!r})'
                .format(self.__class__.__name__, self.options_schema))


class PacketDataField(StructField):
    """
    Field containing some "packet data", used in the Packet
    and EnhancedPacket blocks.

    The packet data is composed of three fields (returned in a tuple):

    - captured len (uint32)
    - packet len (uint32)
    - packet data (captured_len-sized binary data)
    """

    def load(self, stream, endianness):
        captured_len = read_int(stream, 32, False, endianness)
        packet_len = read_int(stream, 32, False, endianness)
        packet_data = read_bytes_padded(stream, captured_len)
        return captured_len, packet_len, packet_data


class SimplePacketDataField(StructField):
    """
    Field containing packet data from a SimplePacket object.

    The packet data is represented by two fields (returned as a tuple):

    - packet_len (uint32)
    - packet_data (packet_len-sized binary data)
    """

    def load(self, stream, endianness):
        packet_len = read_int(stream, 32, False, endianness)
        packet_data = read_bytes_padded(stream, packet_len)
        return packet_len, packet_data


class ListField(StructField):
    """
    A list field is a variable amount of fields of some other type.
    Used for packets containing multiple "items", such as
    :py:class:`~pcapng.blocks.NameResolution`.

    It will keep loading data using a subfield until a
    :py:exc:`~pcapng.exceptions.StreamEmpty` excaption is raised, indicating
    we reached the end of data (note that a sub-field might even "simulate"
    a stream end once it reaches some end marker in the file).

    Values are returned in a list.

    :param subfield: a :py:class:`StructField` sub-class instance to be
        used to read values from the stream.
    """

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

    def __repr__(self):
        return ('{0}({1!r})'.format(self.__class__.__name__, self.subfield))


class NameResolutionRecordField(StructField):
    """
    A name resolution record field contains an item of data used in
    the :py:class:`~pcapng.blocks.NameResolution` block.

    it is composed of three fields:

    - record type (uint16)
    - record length (uint16)
    - payload

    Accepted types are:

    - ``0x00`` - end marker
    - ``0x01`` - ipv4 address resolution
    - ``0x02`` - ipv6 address resolution

    In both cases, the payload is composed of a valid address in the
    selected IP version, followed by domain name up to the field end.
    """

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
    Read "options" from an "options block" in a stream, until a
    ``StreamEmpty`` exception is caught, or an end marker is reached.

    Each option is composed by:

    - option_code (uint16)
    - value_length (uint16)
    - value (value_length-sized binary data)

    The end marker is simply an option with code ``0x0000`` and no payload
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
    Wrapper object used to easily access the contents of an "options"
    field.

    Fields can be accessed either by numerical id or by name (if one was
    specified in the schema).

    .. note::

        When iterating the object (or calling :py:meth:`keys` /
        :py:meth:`iterkeys` / :py:meth:`viewkeys`) string keys will be
        returned if possible in place of numeric keys.  (The purpose of this
        is to achieve better readability, for example, when converting
        to a dictionary).

    :param schema:
        Definition of the known options: a list of 2- or 3-tuples
        (the third argument is optional) representing, respectively,
        the numeric option code, the option name and the value type.

        The following value types are currently supported:

        - ``string``: convert value to a unicode string, using utf-8 encoding
        - ``{u,i}{8,16,32,64}``: (un)signed integer of the specified length
        - ``ipv4``: a single ipv4 address [4 bytes]
        - ``ipv4+mask``: an ipv4 address followed by a netmask [8 bytes]
        - ``ipv6``: a single ipv6 address [16 bytes]
        - ``ipv6+prefix``: an ipv6 address followed by prefix length [17 bytes]
        - ``macaddr``: a mac address [6 bytes]
        - ``euiaddr``: a eui address [8 bytes]

    :param data:
        Initial data for the options. A list of two-tuples: ``(code, value)``.
        Items with the same code may be repeated; only the first one will be
        accessible using subscript ``options[code]``; the others can be
        accessed using :py:meth:`get_all` and related methods

    :param endianness:
        The current endianness of the section these options came from.
        Required in order to load numeric fields.
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
        """Get all values for the given option"""
        return self._get_all_converted(name)

    def get_raw(self, name):
        """Get raw value for the given option"""
        return self._get_raw(name)

    def get_all_raw(self, name):
        """Get all raw values for the given option"""
        return self._get_all_raw(name)

    def iter_all_items(self):
        """
        Similar to :py:meth:`iteritems` but will yield a list of values
        as the second tuple field.
        """
        for key in self:
            yield key, self.get_all(key)

    def __repr__(self):
        args = dict(self.iter_all_items())
        name = self.__class__.__name__
        return '{0}({1!r})'.format(name, args)

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
        _name = self._resolve_name(name)
        try:
            return self.raw_data[_name][0]
        except KeyError:
            raise KeyError(name)

    def _get_all_raw(self, name):
        _name = self._resolve_name(name)
        try:
            return list(self.raw_data[_name])
        except KeyError:
            raise KeyError(name)

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
            return value.decode('utf-8')

        _numeric_types = {
            'u8': 'B', 'i8': 'b',
            'u16': 'H', 'i16': 'h',
            'u32': 'I', 'i32': 'i',
            'u64': 'Q', 'i64': 'q',
        }
        if ftype in _numeric_types:
            return struct.unpack(
                self.endianness + _numeric_types[ftype], value)[0]

        if ftype == 'ipv4':
            return unpack_ipv4(value)

        if ftype == 'ipv4+mask':
            return unpack_ipv4(value[:4]), unpack_ipv4(value[4:8])

        if ftype == 'ipv6':
            return unpack_ipv6(value)

        if ftype == 'ipv6+prefix':
            return (unpack_ipv6(value[:16]),
                    struct.unpack(self.endianness + 'B', value[16]))

        if ftype == 'macaddr':
            return unpack_macaddr(value)

        if ftype == 'euiaddr':
            return unpack_euiaddr(value)

        raise ValueError('Unsupported field type: {0}'.format(ftype))


def struct_decode(schema, stream, endianness='='):
    """
    Decode structured data from a stream, following a schema.

    :param schema:
        a list of two tuples: ````(name, field)``, where ``name`` is a string
        representing the attribute name, and ``field`` is an instance of a
        :py:class:`StructField` sub-class, providing a ``.load()`` method
        to be called on the stream to get the field value.

    :param stream:
        a file-like object, providing a ``.read()`` method, from which data
        will be read.

    :param endianness:
        endianness specifier, as accepted by Python struct module
        (one of ``<>!=``, defaults to ``=``).

    :return:
        a dictionary mapping the field names to decoded data
    """

    decoded = {}
    for name, field in schema:
        decoded[name] = field.load(stream, endianness=endianness)
    return decoded


def struct_encode(schema, obj, outstream, endianness='='):
    """
    In the future, this function will be used to encode a structure into
    a stream. For the moment, it just raises :py:exc:`NotImplementedError`.
    """
    raise NotImplementedError


def struct_decode_string(schema, data):
    """Utility function to pass a string to :py:func:`struct_decode`"""
    return struct_decode(schema, io.BytesIO())


def struct_encode_string(schema, obj):
    """
    Utility function to pass a string to :py:func:`struct_encode`
    and get the result back as a bytes string.
    """
    outstream = io.BytesIO()
    struct_encode(schema, obj, outstream)
    return outstream.getvalue()
