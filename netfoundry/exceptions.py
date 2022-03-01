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
