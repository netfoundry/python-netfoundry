import sys  # open stderr
import unicodedata  # case insensitive compare in Utility
from re import sub

import inflect  # singular and plural nouns
from requests import \
    Session  # HTTP user agent will not emit server cert warnings if verify=False
from urllib3.exceptions import InsecureRequestWarning

from requests import status_codes
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3 import disable_warnings

disable_warnings(InsecureRequestWarning)

class Utility:
    def __init__(self):
        pass

    def camel(self, snake_str):
        first, *others = snake_str.split('_')
        return ''.join([first.lower(), *map(str.title, others)])

    def snake(self, camel_str):
        return sub(r'(?<!^)(?=[A-Z])', '_', camel_str).lower()

    def normalize_caseless(self, text):
        return unicodedata.normalize("NFKD", text.casefold())

    def caseless_equal(self, left, right):
        return self.normalize_caseless(left) == self.normalize_caseless(right)

class LookupDict(dict):
    """Dictionary lookup object."""

    def __init__(self, name=None):
        self.name = name
        super(LookupDict, self).__init__()

    def __repr__(self):
        return '<lookup \'%s\'>' % (self.name)

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

p = inflect.engine()
def plural(singular):
    # if already plural then return, else pluralize
    if singular[-1:] == 's':
        return(singular)
    else:
        return(p.plural_noun(singular))

def singular(plural):
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
    'networks': {
        'embedded': "networkList",
        'create_responses': ["ACCEPTED"]
    },
    'endpoints': {
        'embedded': "endpointList",
        'create_responses': ["OK", "ACCEPTED"]
    },
    'edge-routers': {
        'embedded': "edgeRouterList",
        'create_responses': ["ACCEPTED"]
    },
    'edge-router-policies': {
        'embedded': "edgeRouterPolicyList",
        'create_responses': ["ACCEPTED"]
    },
    'app-wans': {
        'embedded': "appWanList",
        'create_responses': ["OK"]
    },
    'services': {
        'embedded': "serviceList",
        'create_responses': ["ACCEPTED"]
    },
    'service-policies': {
        'embedded': "servicePolicyList",
        'create_responses': ["ACCEPTED"]
    },
    'service-edge-router-policies': {
        'embedded': "serviceEdgeRouterPolicyList",
        'create_responses': ["ACCEPTED"]
    },
    'posture-checks': {
        'embedded': "postureCheckList",
        'create_responses': ["ACCEPTED"]
    }
}

# TODO: [MOP-13441] associate locations with a short list of major geographic regions / continents
MAJOR_REGIONS = {
    "AWS" : {
        "Americas": ("Canada Central","N. California","N. Virginia","Ohio","Oregon","Sao Paulo"),
        "EuropeMiddleEastAfrica": ("Bahrain","Cape Town South Africa","Frankfurt","Ireland","London","Milan","Paris","Stockholm"),
        "AsiaPacific": ("Hong Kong","Mumbai","Seoul","Singapore","Sydney","Tokyo")
    }
}

HOST_PROPERTIES = ["ownerIdentityId", "ipAddress", "port", "provider", "providerInstanceId", "size", "locationMetadataId", "dataCenterId"]

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
    def dec(obj):
        obj.__doc__ = obj.__doc__.format(*args, **kwargs)
        return obj
    return dec


RETRY_STRATEGY = Retry(
    total=3,
    status_forcelist=[413, 429, 503],
    method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"],
    backoff_factor=1
)

DEFAULT_TIMEOUT = 31 # seconds, Gateway Service waits 30s before responding with an error code e.g. 503 and
# so waiting at least 31s is necessary to obtain that information
class TimeoutHTTPAdapter(HTTPAdapter):
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