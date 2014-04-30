"""Generic contsnts"""

# Byte order magic numbers
# ----------------------------------------

ORDER_MAGIC_LE = 0x1a2b3c4d
ORDER_MAGIC_BE = 0x4d3c2b1a

SIZE_NOTSET = 0xffffffffffffffff  # 64bit "-1"

# Endianness constants

ENDIAN_NATIVE = 0  # '='
ENDIAN_LITTLE = 1  # '<'
ENDIAN_BIG = 2  # '>'
