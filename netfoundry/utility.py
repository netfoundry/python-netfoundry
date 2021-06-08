import unicodedata          # case insensitive compare in Utility
import inflect              # singular and plural nouns
import sys                  # open stderr
from re import sub

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
