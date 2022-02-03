"""Interface to NetFoundry management API."""

from . import _version
from .network import Network
from .network_group import NetworkGroup
from .organization import Organization

__version__ = _version.get_versions()['version']
