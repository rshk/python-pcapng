# Option types, used all around
# ------------------------------------------------------------

# Generic options
# ----------------------------------------

# It delimits the end of the optional fields. This block cannot be
# repeated within a given list of options.
OPT_ENDOFOPT = 0

# A UTF-8 string containing a comment that is associated to the
# current block.  "This packet is the beginning of all of our
# problems" / "Packets 17-23 showing a bogus TCP retransmission, as
# reported in bugzilla entry 1486!" / "Captured at the southern plant"
# / "I've checked again, now it's working ok" / ...
OPT_COMMENT = 1

# Section header options
# ----------------------------------------

# An UTF-8 string containing the description of the hardware used to
# create this section.
OPT_SHB_HARDWARE = 2

# An UTF-8 string containing the name of the operating system used to
# create this section.
OPT_SHB_OS = 3

# An UTF-8 string containing the name of the application used to
# create this section.
OPT_SHB_USERAPPL = 4

# Interface options
# ----------------------------------------

# A UTF-8 string containing the name of the device used to capture data.
OPT_IF_NAME = 2

# Variable	A UTF-8 string containing the description of the device
# used to capture data.
OPT_IF_DESCRIPTION = 3

# 8 Interface network address and netmask. This option can be repeated
# multiple times within the same Interface Description Block when
# multiple IPv4 addresses are assigned to the interface.
OPT_IF_IPV4ADDR = 4

# 17 Interface network address and prefix length (stored in the last
# byte). This option can be repeated multiple times within the same
# Interface Description Block when multiple IPv6 addresses are
# assigned to the interface.
OPT_IF_IPV6ADDR = 5

# 6	Interface Hardware MAC address (48 bits).
OPT_IF_MACADDR = 6

# 8	Interface Hardware EUI address (64 bits), if available.
OPT_IF_EUIADDR = 7

# 8	Interface speed (in bps).
OPT_IF_SPEED = 8

# 1 Resolution of timestamps. If the Most Significant Bit is equal to
# zero, the remaining bits indicates the resolution of the timestamp
# as as a negative power of 10 (e.g. 6 means microsecond resolution,
# timestamps are the number of microseconds since 1/1/1970). If the
# Most Significant Bit is equal to one, the remaining bits indicates
# the resolution as as negative power of 2 (e.g. 10 means 1/1024 of
# second). If this option is not present, a resolution of 10^-6 is
# assumed (i.e. timestamps have the same resolution of the standard
# 'libpcap' timestamps).
OPT_IF_TSRESOL = 9

# 4	Time zone for GMT support (TODO: specify better).
OPT_IF_TZONE = 10

# variable The filter (e.g. "capture only TCP traffic") used to
# capture traffic. The first byte of the Option Data keeps a code of
# the filter used (e.g. if this is a libpcap string, or BPF bytecode,
# and more). More details about this format will be presented in
# Appendix XXX (TODO). (TODO: better use different options for
# different fields? e.g. if_filter_pcap, if_filter_bpf, ...)
OPT_IF_FILTER = 11

# variable A UTF-8 string containing the name of the operating system
# of the machine in which this interface is installed. This can be
# different from the same information that can be contained by the
# Section Header Block (Section 3.1) because the capture can have been
# done on a remote machine.
OPT_IF_OS = 12

# 1 An integer value that specified the length of the Frame Check
# Sequence (in bits) for this interface. For link layers whose FCS
# length can change during time, the Packet Block Flags Word can be
# used (see Appendix A).
OPT_IF_FCSLEN = 13

# 8 A 64 bits integer value that specifies an offset (in seconds) that
# must be added to the timestamp of each packet to obtain the absolute
# timestamp of a packet. If the option is missing, the timestamps
# stored in the packet must be considered absolute timestamps. The
# time zone of the offset can be specified with the option
# if_tzone. TODO: won't a if_tsoffset_low for fractional second
# offsets be useful for highly syncronized capture systems?
OPT_IF_TSOFFSET = 14


# 4  A flags word containing link-layer information. A complete
# specification of the allowed flags can be found in Appendix A.  0
OPT_EPB_FLAGS = 2

# variable  This option contains a hash of the packet. The first byte
# specifies the hashing algorithm, while the following bytes contain
# the actual hash, whose size depends on the hashing algorithm, and
# hence from the value in the first bit. The hashing algorithm can be:
# 2s complement (algorithm byte = 0, size=XXX), XOR (algorithm byte =
# 1, size=XXX), CRC32 (algorithm byte = 2, size = 4), MD-5 (algorithm
# byte = 3, size=XXX), SHA-1 (algorithm byte = 4, size=XXX). The hash
# covers only the packet, not the header added by the capture driver:
# this gives the possibility to calculate it inside the network
# card. The hash allows easier comparison/merging of different capture
# files, and reliable data transfer between the data acquisition
# system and the capture library. (TODO: the text above uses "first
# bit", but shouldn't this be "first byte"?!?)  TODO: give a good
# example
OPT_EPB_HASH = 3

# 8  A 64bit integer value specifying the number of packets lost (by
# the interface and the operating system) between this packet and the
# preceding one.  0
OPT_EPB_DROPCOUNT = 4


# 4  Same as epb_flags of the enhanced packet block.  0
OPT_PACK_FLAGS = 2

# variable  Same as epb_hash of the enhanced packet block.  TODO: give
# a good example
OPT_PACK_HASH = 3

# 0  It delimits the end of name resolution records. This record is
# needed to determine when the list of name resolution records has
# ended and some options (if any) begin.
OPT_NRES_ENDOFRECORD = 0

# Variable  Specifies an IPv4 address (contained in the first 4
# bytes), followed by one or more zero-terminated strings containing
# the DNS entries for that address.  127 0 0 1 "localhost"
OPT_NRES_IP4RECORD = 1

# Variable  Specifies an IPv6 address (contained in the first 16
# bytes), followed by one or more zero-terminated strings containing
# the DNS entries for that address.  TODO: give a good example
OPT_NRES_IP6RECORD = 2

# Variable  A UTF-8 string containing the name of the machine (DNS
# server) used to perform the name resolution.  "our_nameserver"
OPT_NS_DNSNAME = 2

# 4  The IPv4 address of the DNS server.  192 168 0 1
OPT_NS_DNSIP4ADDR = 3

# 16  The IPv6 address of the DNS server.  TODO: give a good example
OPT_NS_DNSIP6ADDR = 4


# 8 Time in which the capture started; time will be stored in two
# blocks of four bytes each. The format of the timestamp is the same
# already defined in the Enhanced Packet Block (Section 3.3).
OPT_ISB_STARTTIME = 2

# 8 Time in which the capture ended; ; time will be stored in two
# blocks of four bytes each. The format of the timestamp is the same
# already defined in the Enhanced Packet Block (Section 3.3).
OPT_ISB_ENDTIME = 3

# 8 Number of packets received from the physical interface starting
# from the beginning of the capture.
OPT_ISB_IFRECV = 4

# 8 Number of packets dropped by the interface due to lack of
# resources starting from the beginning of the capture.
OPT_ISB_IFDROP = 5

# 8 Number of packets accepted by filter starting from the beginning
# of the capture.
OPT_ISB_FILTERACCEPT = 6

# 8 Number of packets dropped by the operating system starting from
# the beginning of the capture.
OPT_ISB_OSDROP = 7

# 8 Number of packets delivered to the user starting from the
# beginning of the capture. The value contained in this field can be
# different from the value 'isb_filteraccept - isb_osdrop' because
# some packets could still lay in the OS buffers when the capture
# ended.
OPT_ISB_USRDELIV = 8
