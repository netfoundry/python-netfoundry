""" Interface to NetFoundry API
"""

from .network import Network
from .network_group import NetworkGroup
from .organization import Organization

from . import _version
__version__ = _version.get_versions()['version']
