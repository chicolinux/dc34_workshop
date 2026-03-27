"""
Red Team Toolkit — Fuzzer Module

Wraps custom protocol fuzzing from Module 5.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from module5.custom_fuzzer import fuzz_server, is_server_alive
from module5.dns_fuzzer    import fuzz_dns


def fuzz_service(
    target:   str,
    port:     int = 9000,
    iters:    int = 1000,
    seed:     int | None = None,
) -> list[dict]:
    """
    Fuzz the custom DC34 protocol service on target:port.

    Returns list of crash dicts: [{'iteration': N, 'file': 'path/to/crash.pcap'}]
    """
    return fuzz_server(target, port, max_iter=iters, seed=seed)


def fuzz_dns_service(
    target:   str,
    iters:    int = 500,
    delay:    float = 0.05,
    seed:     int | None = None,
) -> None:
    """Fuzz a DNS server on target."""
    fuzz_dns(target, iters=iters, seed=seed, delay=delay)


def check_alive(target: str, port: int = 9000) -> bool:
    """Quick liveness check using canary probe."""
    return is_server_alive(target, port)
