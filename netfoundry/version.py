"""Print the version string."""
from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("netfoundry")
    print("v"+__version__)
except PackageNotFoundError:
    # package is not installed
    raise Exception("ERROR: 'netfoundry' package is not installed.")
