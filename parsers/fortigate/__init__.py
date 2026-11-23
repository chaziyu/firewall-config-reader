"""FortiGate (FortiOS) CLI configuration parsers."""

from .bgp import FortiGateBGPParser
from .core import FortiGateParser
from .logs import LOGSparserMixin
from .security import SecurityProfileMixin
from .system import SystemParserMixin
from .user import UserParserMixin
from .vpn import VPNParserMixin
from .wifi import WiFiParserMixin

__all__ = [
    "FortiGateBGPParser",
    "FortiGateParser",
    "LOGSparserMixin",
    "SecurityProfileMixin",
    "SystemParserMixin",
    "UserParserMixin",
    "VPNParserMixin",
    "WiFiParserMixin",
]
