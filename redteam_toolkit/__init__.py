"""
Red Team Toolkit — DC34 Scapy Workshop

A Python package that wraps all workshop modules into reusable,
importable primitives for building offensive tools.

Quick start:
    from redteam_toolkit.recon   import sweep, syn_scan
    from redteam_toolkit.mitm    import ArpMitm
    from redteam_toolkit.fuzzer  import fuzz_service
    from redteam_toolkit.covert  import IcmpC2, DnsExfil
"""

__version__ = "1.0.0"
__author__  = "DC34 Workshop"

from .recon  import sweep, syn_scan, os_fingerprint
from .mitm   import ArpMitm
from .fuzzer import fuzz_service
from .covert import IcmpC2, DnsExfil

__all__ = [
    "sweep",
    "syn_scan",
    "os_fingerprint",
    "ArpMitm",
    "fuzz_service",
    "IcmpC2",
    "DnsExfil",
]
