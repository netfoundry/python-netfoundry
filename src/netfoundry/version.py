"""Print the version string."""
from ._version import get_versions

try:
    print("v"+get_versions()['version'] )
except:
    # package is not installed
    raise Exception("ERROR: could not do get_version() from versioneer.")
