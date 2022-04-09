"""Interface to NetFoundry management API."""

import sys

from . import _version

try:
    assert (sys.version_info[0] == 3), "Python version must be 3"
except Exception as e:
    print (e)
    exit(1)

__version__ = _version.get_versions()['version']

from . import _version
__version__ = _version.get_versions()['version']
