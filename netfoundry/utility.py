"""Shared helper functions, constants, and classes."""

import logging
import sys  # open stderr
import unicodedata  # case insensitive compare in Utility
from dataclasses import dataclass, field
from re import sub
from uuid import UUID  # validate UUIDv4 strings

import inflect  # singular and plural nouns
import jwt
from requests import \
    Session  # HTTP user agent will not emit server cert warnings if verify=False
from requests import status_codes
from requests.adapters import HTTPAdapter
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

disable_warnings(InsecureRequestWarning)

class Utility:
    """Shared functions intended for use with and within the module."""

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

    def jwt_decode(self, token):
        # TODO: figure out how to stop doing this because the token is for the
        # API, not this app, and so may change algorithm unexpectedly or stop
        # being a JWT altogether, currently needed to build the URL for HTTP
        # requests, might need to start using env config
        """Parse the token and return claimset."""
        try:
            claim = jwt.decode(jwt=token, algorithms=["RS256"], options={"verify_signature": False})
        except jwt.exceptions.PyJWTError:
            logging.error("failed to parse bearer token as JWT")
            raise
        except:
            logging.error("unexpect error parsing JWT")
            raise
        return claim

    def is_jwt(self, token):
        """If is a JWT then True."""
        try:
            self.jwt_decode(token)
        except jwt.exceptions.PyJWTError:
            return False
        except:
            logging.error("unexpect error parsing JWT")
            raise
        else:
            return True
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
    """Adapt legacy function to logging."""
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

def camel(kebab, case: str="lower"):                # "lower" dromedary or "upper" Pascal 
    kebab_words = kebab.split('-')
    camel_words = list()
    if case in ["lower","dromedary"]:
        camel_words.append(kebab_words[0].lower())  # first word is lowercase 
    elif case in ["upper","pascal"]:
        camel_words.append(kebab_words[0].upper())  # first word is uppercase
    else:
        raise Exception("param 'case' wants 'lower' or 'upper'")
    for word in kebab_words[1:]:                    # subsequent words are capitalized (cameled)
        lower_word = word.lower()
        capital = lower_word[0].upper()
        camel_word = capital+lower_word[1:]
        camel_words.append(camel_word)
    camel = ''.join(camel_words)
    return camel


# parent class so that type checking be re-used for other child classes
@dataclass
class ResourceTypeParent:
    """Parent class for ResourceType class."""
    
    def __post_init__(self):
        """Enforce typed fields in resource spec."""
        for (name, field_type) in self.__annotations__.items():
            if not isinstance(self.__dict__[name], field_type):
                current_type = type(self.__dict__[name])
                raise TypeError(f"The field `{name}` was assigned by `{current_type}` instead of `{field_type}`")

# the instance's attributes can not be frozen because we're computing the
# _embedded key and assigning post-init
@dataclass(frozen=False)
class ResourceType(ResourceTypeParent):
    """Typed resource type spec.
    
    As close as I could get to a Go struct. This helps us to suggest possible
    operations such as all resource types in the network domain that can be
    mutated (C_UD).
    """

    name: str                                               # plural form as kebab-case e.g. edge-routers
    domain: str                                             # most are in network, organization
    mutable: bool                                           # createable, editable, or deletable
    embeddable: bool                                        # legal to request embedding in a parent resource in same domain
    _embedded: str = field(default='default')               # the key under which lists are found in the API e.g. networkControllerList 
                                                            #   (computed if not provided as dromedary case singular)
    create_responses: list = field(default_factory=list)    # expected HTTP response codes for create operation
    create_template: dict = field(default_factory=lambda: {
        'hint': "No template was found for this resource type. Replace the contents of this buffer with the request body as YAML or JSON to create a resource. networkId will be added automatically."
    })                                                      # object to load when creating from scratch in nfctl

    def __post_init__(self):
        """Compute and assign _embedded if not supplied and then check types in parent class."""
        if self._embedded == 'default':
            singular_name = singular(self.name)
            camel_name = camel(singular_name)+'List'       # edgeRouterList
            self._embedded = camel_name
        return super().__post_init__()

RESOURCES = {
    'data-centers': ResourceType(
        name='data-centers',
        domain='network',
        _embedded='dataCenters',      # TODO: raise a bug report because this inconcistency forces consumers to make an exception for this type
        mutable=False,
        embeddable=False
    ),
    'organizations': ResourceType(
        name='organizations',
        domain='organization',
        mutable=False,
        embeddable=False
    ),
    'network-groups': ResourceType(
        name='network-groups',
        domain='network-group',
        _embedded='organizations',    # TODO: prune this exception when groups migrate to the Core network domain
        mutable=False,
        embeddable=False
    ),
    'networks': ResourceType(
        name='networks',
        domain='network',
        mutable=True,
        embeddable=False,
        create_responses=["ACCEPTED"],
        create_template={
            "name": "Name",
            "locationCode": "us-east-1",
            "size": "small",
            "networkGroupId": None
        }
    ),
    'network-controllers': ResourceType(
        name='network-controllers',
        domain="network",
        mutable=False,
        embeddable=True,
    ),
    'identities': ResourceType(
        name='identities',
        domain='organization',
        mutable=False,              # TODO: C_UD not yet implemented here in client for org domain
        embeddable=False            # TODO: embedding not yet implemented in API for org domain
    ),
    'hosts': ResourceType(
        name='hosts',
        domain='network',
        mutable=False,
        embeddable=True
    ),
    'endpoints': ResourceType(
        name='endpoints',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
        create_template={
            "attributes": [],
            "enrollmentMethod": {"ott": True},
            "name": "Name"
        }),
    'edge-routers': ResourceType(
        name='edge-routers',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"],
    ),
    'edge-router-policies': ResourceType(
        name='edge-router-policies',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["OK", "ACCEPTED"]
    ),
    'app-wans': ResourceType(
        name='app-wans',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["OK", "ACCEPTED"]
    ),
    'services': ResourceType(
        name='services',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"]
    ),
    'service-policies': ResourceType(
        name='service-policies',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"]
    ),
    'service-edge-router-policies': ResourceType(
        name='service-edge-router-policies',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"]
    ),
    'posture-checks': ResourceType(
        name='posture-checks',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"]
    ),
    'certificate-authorities': ResourceType(
        name='certificate-authorities',
        domain='network',
        mutable=True,
        embeddable=True,
        create_responses=["ACCEPTED"]
    )
}

NETWORK_RESOURCES = {type:spec for type,spec in RESOURCES.items() if spec.domain == "network"}
MUTABLE_NETWORK_RESOURCES = {type:spec for type,spec in RESOURCES.items() if spec.domain == "network" and spec.mutable}

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
