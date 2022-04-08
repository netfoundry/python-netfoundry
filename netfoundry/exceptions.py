#!/usr/bin/env python
"""Exceptions class"""


class NFAPIError(Exception):
    """Base-class for all exceptions raised by this module."""


class NFAPINetworkNoHosts(NFAPIError):
    """NFAPINetwork has no valid hosts."""


class NFAPINetworkDeleted(NFAPIError):
    """Network has already been deleted."""


class NFAPINetworkNotProvisioned(NFAPIError):
    """Network has not been provisioned."""


class NFAPINetworkControllerMissing(NFAPIError):
    """Network must have at least 1 network controller."""


class NFAPIHostDeleted(NFAPIError):
    """Host has already been deleted."""


class NFAPIHostCustomerHosted(NFAPIError):
    """Host is customer hosted."""


class NFAPIEdgeRouterNotProvisioned(NFAPIError):
    """Network host has not been provisioned."""


class NFAPINoCredentials(NFAPIError):
    """Unable to obtain a token because no credentials were configured."""


class UnknownResourceType(NFAPIError):
    """Unknown resource type."""

    def __init__(self, resource_type: str, valid_types: list) -> None:
        """Add the type as an attribute to this instance."""
        self.resource_type = resource_type
        self.valid_types = valid_types

    # consume valid types as param to avoid circular import with .utility
    def __str__(self):
        """Report the invalid type if provided, finally report valid types."""
        if self.resource_type is not None:
            return f"Not a valid resource type: '{self.resource_type}'. Try one of: {', '.join(self.valid_types)}"
        else:
            return f"Not a valid resource type. Try one of: {', '.join(self.valid_types)}"


class NeedUserInput(NFAPIError):
    """Need user input to confirm action."""


class NetworkBoundaryViolation(NFAPIError):
    """Network domain resource accessed across a network boundary."""
