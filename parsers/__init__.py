"""Firewall configuration parsers for FortiGate (FortiOS) and Palo Alto (PAN-OS)."""

from parsers.base import BaseFirewallParser
from parsers.fortigate import FortiGateParser
from parsers.paloalto import (
    PaloAltoParser,
    PaloDashboardParser,
    PaloDeviceParser,
    PaloNetworkParser,
    PaloObjectsParser,
    PaloPoliciesParser,
)

__all__ = [
    "BaseFirewallParser",
    "FortiGateParser",
    "PaloAltoParser",
    "PaloDashboardParser",
    "PaloDeviceParser",
    "PaloNetworkParser",
    "PaloObjectsParser",
    "PaloPoliciesParser",
]
