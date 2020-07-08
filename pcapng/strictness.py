"""
Module for alerting the user when attempting to do things with pcapng that
aren't strictly valid.
"""

import warnings

from pcapng.exceptions import PcapngStrictnessError, PcapngStrictnessWarning

STRICTNESS_NONE = 0  # No warnings, do what you want
STRICTNESS_WARN = 1  # Do what you want, but warn of potential issues
STRICTNESS_FIX = 2  # Warn of potential issues, fix *if possible*
STRICTNESS_FORBID = 3  # raise exception on potential issues

strictness = STRICTNESS_FORBID


def problem(msg):
    "Warn or raise an exception with the given message."
    if strictness == STRICTNESS_FORBID:
        raise PcapngStrictnessError(msg)
    elif strictness in (STRICTNESS_WARN, STRICTNESS_FIX):
        warnings.warn(PcapngStrictnessWarning(msg))


def warn(msg):
    "Show a warning with the given message."
    if strictness > STRICTNESS_NONE:
        warnings.warn(PcapngStrictnessWarning(msg))


def should_fix():
    "Helper function for showing code used to fix questionable pcapng data."
    return strictness == STRICTNESS_FIX
