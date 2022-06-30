"""Print the version string."""
from ._version import get_versions
print("v"+get_versions()['version'])
