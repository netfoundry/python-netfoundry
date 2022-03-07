"""Shared helper functions, constants, and classes."""

import logging
import sys  # open stderr
import unicodedata  # case insensitive compare in Utility
from re import sub
from uuid import UUID  # validate UUIDv4 strings

import inflect  # singular and plural nouns
from requests import \
    Session  # HTTP user agent will not emit server cert warnings if verify=False
from requests import status_codes
from requests.adapters import HTTPAdapter
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

disable_warnings(InsecureRequestWarning)

class Utility:
    """Shared functions intended for use within the module and without."""

    def __init__(self):
        """No-op."""
        pass

    def camel(self, snake_str):
        """Convert a string from snake case to camel case."""
        first, *others = snake_str.split('_')
        return ''.join([first.lower(), *map(str.title, others)])

    def snake(self, camel_str):
        """Convert a string from camel case to snake case."""
        return sub(r'(?<!^)(?=[A-Z])', '_', camel_str).lower()

    def normalize_caseless(self, text):
        """Normalize a string as lowercase unicode KD form.
        
        The normal form KD (NFKD) will apply the compatibility decomposition,
        i.e. replace all compatibility characters with their equivalents.
        """
        return unicodedata.normalize("NFKD", text.casefold())

    def caseless_equal(self, left, right):
        """Compare the KD normal form of left, right strings."""
        return self.normalize_caseless(left) == self.normalize_caseless(right)

class LookupDict(dict):
    """Helper class to create a lookup dictionary from a set."""

    def __init__(self, name=None):
        """Initialize a lookup dictionary."""
        self.name = name
        super(LookupDict, self).__init__()

    def __repr__(self):
        return '<lookup \'%s\'>' % (self.name)

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)

def is_uuidv4(string: str):
    """Test if string is valid UUIDv4."""
    try: UUID(string, version=4)
    except ValueError:
        return False
    else:
        return True

def eprint(*args, **kwargs):
    logging.debug(*args, **kwargs)

p = inflect.engine()
def plural(singular):
    """Pluralize a singular form."""
    # if already plural then return, else pluralize
    if singular[-1:] == 's':
        return(singular)
    else:
        return(p.plural_noun(singular))

def singular(plural):
    """Singularize a plural form."""
    return(p.singular_noun(plural))

STATUSES_BY_CODE = {
    100: ('new', 'created'),
    200: ('building', 'incomplete', 'allocated'),
    300: ('active', 'complete', 'provisioned'),
    400: ('registered', 'enrolled'),
    500: ('error', 'server_error'),
    600: ('updating', 'modifying'),
    800: ('deleting', 'released', 'decommissioned'),
    900: ('defunct', 'deleted')
}

CODES = LookupDict(name='statuses')
for code, titles in STATUSES_BY_CODE.items():
    for title in titles:
        setattr(CODES, title.upper(), code)

RESOURCES = {
    'data-centers': {
        'embedded': "dataCenters",
        'domain': "network"
    },
    'organizations': {
        'embedded': "",
        'domain': "organization"
    },
    'network-groups': {
        'embedded': "organizations",
        'domain': "network-group"
    },
    'networks': {
        'embedded': "networkList",
        'domain': "network",
        'create_responses': ["ACCEPTED"],
        'create_template': {
            "name": "Name",
            "locationCode": "us-east-1",
            "size": "small",
            "networkGroupId": "a7de7a6d-9b05-4e00-89e0-937498c49e0a"
        }
    },
    'network-controllers': {
        'embedded': "networkControllerList",
        'domain': "network"
    },
    'identities': {
        'embedded': "",
        'domain': "organization"
    },
    'hosts': {
        'embedded': "hostList",
        'domain': "network"
    },
    'endpoints': {
        'embedded': "endpointList",
        'domain': "network",
        'create_responses': ["ACCEPTED"],
        'create_template': {
            "attributes": [],
            "enrollmentMethod": {"ott": True},
            "name": "Name"
        }
    },
    'edge-routers': {
        'embedded': "edgeRouterList",
        'domain': "network",
        'create_responses': ["ACCEPTED"]
    },
    'edge-router-policies': {
        'embedded': "edgeRouterPolicyList",
        'domain': "network",
        'create_responses': ["OK", "ACCEPTED"]
    },
    'app-wans': {
        'embedded': "appWanList",
        'domain': "network",
        'create_responses': ["OK"]
    },
    'services': {
        'embedded': "serviceList",
        'domain': "network",
        'create_responses': ["ACCEPTED"],
        'create_template': {"this": 1}
    },
    'service-policies': {
        'embedded': "servicePolicyList",
        'domain': "network",
        'create_responses': ["ACCEPTED"]
    },
    'service-edge-router-policies': {
        'embedded': "serviceEdgeRouterPolicyList",
        'domain': "network",
        'create_responses': ["ACCEPTED"]
    },
    'posture-checks': {
        'embedded': "postureCheckList",
        'domain': "network",
        'create_responses': ["ACCEPTED"]
    },
    'certificate-authorities': {
        'embedded': "certificateAuthorityList",
        'domain': "network",
        'create_responses': ["ACCEPTED"]
    }
}

NETWORK_RESOURCES = {key: RESOURCES[key] for key in RESOURCES.keys() if RESOURCES[key]['domain'] == "network"}

# TODO: [MOP-13441] associate locations with a short list of major geographic regions / continents
MAJOR_REGIONS = {
    "AWS" : {
        "Americas": ("Canada Central","N. California","N. Virginia","Ohio","Oregon","Sao Paulo"),
        "EuropeMiddleEastAfrica": ("Bahrain","Cape Town South Africa","Frankfurt","Ireland","London","Milan","Paris","Stockholm"),
        "AsiaPacific": ("Hong Kong","Mumbai","Seoul","Singapore","Sydney","Tokyo")
    }
}

DC_PROVIDERS = ["AWS", "AZURE", "GCP", "OCP"]

EXCLUDED_PATCH_PROPERTIES = {
    "edge-routers": ["registration"],
    "services": [],
    "endpoints": [],
    "edge-router-policies": [],
    "networks": [],
    "app-wans": [],
    "posture-checks": []
}

VALID_SERVICE_PROTOCOLS = ["tcp", "udp"]
VALID_SEPARATORS = '[:-]' # : or - will match regex pattern

def docstring_parameters(*args, **kwargs):
    """Part a method's __doc__ string with format()."""
    def decorated(ref):
        ref.__doc__ = ref.__doc__.format(*args, **kwargs)
        return ref
    return decorated


RETRY_STRATEGY = Retry(
    total=3,
    status_forcelist=[413, 429, 503],
    method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"],
    backoff_factor=1
)

DEFAULT_TIMEOUT = 31 # seconds, Gateway Service waits 30s before responding with an error code e.g. 503 and
# so waiting at least 31s is necessary to obtain that information
class TimeoutHTTPAdapter(HTTPAdapter):
    """Configure Python requests library to have retry and timeout defaults."""

    def __init__(self, *args, **kwargs):
        self.timeout = DEFAULT_TIMEOUT
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)

http = Session()
# Mount it for both http and https usage
adapter = TimeoutHTTPAdapter(timeout=DEFAULT_TIMEOUT, max_retries=RETRY_STRATEGY)
http.mount("https://", adapter)
http.mount("http://", adapter)

STATUS_CODES = status_codes
