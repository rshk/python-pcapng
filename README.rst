Python-pcapng
#############

Python library to parse the pcap-ng format used by newer versions
of dumpcap & similar tools (wireshark, winpcap, ...).

Format specification is here:

http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html


Why this library?
=================

- I need to decently extract some information from a bunch of pcap-ng
  files, but apparently tcpdump has some problems reading those files,

  I couldn't find other nice tools nor Python bindings to a library
  able to parse this format, so..

- In general, it appears there are (quite a bunch of!) Python modules
  to parse the old (much simpler) format, but nothing for the new one.

  And, they usually completely lack any form of documentation.
  I promise this thing will be 100% documented, once I get to a stable
  enough architecture for it :)


Isn't it slow?
==============

Yes, I guess it would be much slower than something written in C,
but I'm much better at Python than C.

But I need to get things done, and CPU time is not that expensive :)

(Maybe I'll give a try porting the thing to Cython to speed it up, but
anyways, pure-Python libraries are always useful, eg. for PyPy).


How do I use it?
================

An usage example is contained in ``example.py``, but the project is
still very young, so things might change completely.

Proper documentation is coming as soon as architecture is stable enough
(aka, there is something to document).

Keep tuned, and suggestions / contributions are welcome.
