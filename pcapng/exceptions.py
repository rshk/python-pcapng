class PcapngException(Exception):
    pass


class PcapngLoadError(PcapngException):
    pass


class PcapngDumpError(PcapngException):
    pass


class StreamEmpty(PcapngLoadError):  # End of stream
    """
    End of the stream read: zero bytes read (or got EOFError)
    """
    pass


class CorruptedFile(PcapngLoadError):
    pass


class TruncatedFile(PcapngLoadError):
    """
    Was expecting to read data, but not enough bytes were read
    (but still not zero!).
    """
    pass


class BadMagic(PcapngLoadError):
    pass
