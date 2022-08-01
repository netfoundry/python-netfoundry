"""Use a network group and find its networks."""

# from .organization import Organization
from .network import Networks
from .utility import NET_RESOURCES, STATUS_CODES, caseless_equal, create_generic_resource, find_generic_resources, get_generic_resource_by_url, http, is_uuidv4, normalize_caseless


class NetworkGroup:
    """use a network group by name or ID.

    The default is to use the first network group available to the organization of the caller.
    """

    def __init__(self, Organization: object, network_group_id: str = None, network_group_name: str = None, group: str = None):
        """Initialize the network group class with a group name or ID."""
        # self.organization = Organization
        self.logger = Organization.logger
        self.network_groups = Organization.find_network_groups_by_organization()
        if (not network_group_id and not network_group_name) and group:
            self.logger.debug(f"got 'group' = '{group}' which could be a short name or id")
            if is_uuidv4(group):
                network_group_id = group
                self.logger.debug(f"group value '{network_group_name}' is detected as UUIDv4")
            else:
                network_group_name = normalize_caseless(group)
                self.logger.debug(f"group value '{network_group_name}' is not detected as UUIDv4, assuming it's a group short name")
        if network_group_id:
            self.network_group_id = network_group_id
            network_group_matches = [ng for ng in self.network_groups if ng['id'] == network_group_id]
            if len(network_group_matches) == 1:
                self.network_group_name = network_group_matches[0]['shortName']
                self.logger.debug(f"found one match for group id '{network_group_id}'")
            else:
                raise RuntimeError(f"there was not exactly one network group matching the id '{network_group_id}'")
        # TODO: review the use of org short name ref https://mattermost.tools.netfoundry.io/netfoundry/pl/gegyzuybypb9jxnrw1g1imjywh
        elif network_group_name:
            self.network_group_name = network_group_name
            network_group_matches = [ng for ng in self.network_groups if caseless_equal(ng['shortName'], self.network_group_name)]
            if len(network_group_matches) == 1:
                self.network_group_id = network_group_matches[0]['id']
                self.logger.debug(f"found one match for group short name '{network_group_name}'")
            else:
                raise RuntimeError(f"there was not exactly one network group matching the name '{network_group_name}'")
        elif len(self.network_groups) > 0:
            # first network group is typically the only network group
            self.network_group_id = self.network_groups[0]['id']
            self.network_group_name = normalize_caseless(self.network_groups[0]['shortName'])
            # warn if there are other groups
            if len(self.network_groups) > 1:
                self.logger.warning(f"using first network group {self.network_group_name} and ignoring {len(self.network_groups) - 1} other(s) e.g. {self.network_groups[1]['shortName']}, etc...")
            elif len(self.network_groups) == 1:
                self.logger.debug(f"using the only available network group: {self.network_group_name}")
        else:
            raise RuntimeError("need at least one network group in organization")

        self.token = Organization.token
        self.proxies = Organization.proxies
        self.verify = Organization.verify
        self.audience = Organization.audience
        self.environment = Organization.environment
        self.describe = Organization.get_network_group(self.network_group_id)
        self.id = self.network_group_id
        self.name = self.network_group_name
        self.vanity = normalize_caseless(Organization.label)
        if self.environment == "production":
            self.nfconsole = f"https://{self.vanity}.nfconsole.io"
        else:
            self.nfconsole = f"https://{self.vanity}.{self.environment}-nfconsole.io"

        self.network_ids_by_normal_name = dict()
        for net in Organization.get_networks_by_group(network_group_id=self.network_group_id):
            self.network_ids_by_normal_name[normalize_caseless(net['name'])] = net['id']

    def map_region_name_by_provider_and_location_code(self):
        """Map all region providers by their location code."""
        region_map = dict()
        networks = Networks(self)
        for region in networks.find_regions(providers=['OCI', 'AWS']):
            region_map[region['locationCode']] = region['provider']
        return(region_map)
    nc_data_centers_by_location = map_region_name_by_provider_and_location_code

    # resolve network UUIDs by name
    def network_id_by_normal_name(self, name):
        """Find network ID in group by case-insensitive (caseless, normalized) name.

        Case-insensitive uniqueness is enforced by the API for each type of entity.
        """
        caseless = normalize_caseless(name)
        if self.network_ids_by_normal_name.get(caseless):
            return(self.network_ids_by_normal_name[caseless])
        else:
            raise RuntimeError(f"no network named '{name}' in this network group")

    def network_exists(self, name: str, deleted: bool = False):
        """Check if a network exists in the current group.

        :param name: the case-insensitive string to search
        :param deleted: include deleted networks in results
        """
        if self.network_ids_by_normal_name.get(normalize_caseless(name)):
            return(True)
        else:
            return(False)

    def find_regions(self, **kwargs):
        """Find network controller data center regions."""
        return(Networks.find_regions(**kwargs))
    nc_data_centers = find_regions

    # provide a compatible alias
    get_controller_data_centers = nc_data_centers

    def get_product_metadata(self, is_active: bool = True):
        """
        Get product version metadata.

        :param is_active: filter for only active product versions
        :param product_version: semver string of a single version to get, default is all versions
        """
        url = self.audience+'product-metadata/v2/download-urls.json'
        all_product_metadata, status_symbol = get_generic_resource_by_url(setup=self, url=url)
        if is_active:
            filtered_product_metadata = dict()
            for product in all_product_metadata.keys():
                if all_product_metadata[product]['active']:
                    filtered_product_metadata[product] = all_product_metadata[product]
            return (filtered_product_metadata)
        else:
            return (all_product_metadata)

    def find_network_versions(self, is_active: bool = True):
        """Find active network versions."""
        url = self.audience+NET_RESOURCES['network-versions'].find_url
        network_versions = list()
        for i in find_generic_resources(setup=self, url=url, active=is_active, embedded=NET_RESOURCES['network-versions']._embedded):
            # self.logger.debug(f"found a page of versions {i}")
            network_versions.extend(i)
        return network_versions

    list_product_versions = find_network_versions

    def find_latest_network_version(self, network_versions: list = list(), is_active: bool = True):
        """Get the highest network version."""
        if not network_versions:
            network_versions = [v['networkVersion'] for v in self.find_network_versions(is_active=is_active)]
        from distutils.version import LooseVersion
        return sorted(network_versions, key=LooseVersion)[-1]

    find_latest_product_version = find_latest_network_version

    def create_network(self, name: str, network_group_id: str = None, location: str = "eu-amsterdam-1", provider: str = "OCI", version: str = None, size: str = "medium", wait: int = 1200, sleep: int = 10, **kwargs):
        """
        Create a network in this network group.

        :param name: required network name
        :param network_group: optional network group ID
        :param location: optional data center region name in which to create
        :param version: optional product version string like 7.3.17
        :param size: optional network configuration metadata name from /core/v2/network-configs e.g. "medium"
        """

        # map incongruent api keys from kwargs to function params ("name", "size" are congruent)
        for param, value in kwargs.items():
            if param == 'networkGroupId':
                if network_group_id:
                    self.logger.debug("clobbering param 'network_group_id' with kwarg 'networkGroupId'")
                network_group_id = value
            elif param == 'locationCode':
                if location:
                    self.logger.debug("clobbering param 'location' with kwarg 'locationCode'")
                location = value
            elif param == 'productVersion':
                if version:
                    self.logger.debug("clobbering param 'version' with kwarg 'productVersion'")
                version == value
            else:
                self.logger.warn(f"ignoring unexpected keyword argument '{param}'")

        networks = Networks(setup=self)
        matching_regions = networks.find_regions(provider=provider, location_code=location)
        if not len(matching_regions) == 1:
            raise RuntimeError(f"failed to find exactly one match for requested controller region '{location}'")

        body = {
            "name": name.strip('"'),
            "provider": provider,
            "region": location,
            "size": size,
        }

        if network_group_id:
            body["networkGroupId"] = network_group_id
        else:
            body["networkGroupId"] = self.network_group_id

        if version and not version == "default":
            network_versions = self.find_network_versions()
            if version == "latest":
                body['productVersion'] = self.find_latest_network_version(network_versions)
            elif version in network_versions:
                body['productVersion'] = version
            else:
                raise RuntimeError(f"invalid version '{version}'. Expected one of {network_versions}")
        url = self.audience+'core/v2/networks'
        resource = create_generic_resource(setup=self, url=url, body=body, wait=wait, sleep=sleep)
        return(resource)

    def delete_network(self, network_id=None, network_name=None):
        """
        Delete a network.

        :param id: optional network UUID to delete
        :param name: optional network name to delete
        """
        try:
            if network_id:
                try:
                    network_name = next(name for name, uuid in self.network_ids_by_normal_name.items() if uuid == network_id)
                except StopIteration:
                    self.logger.debug(f"failed to resolve {network_id} to a network name")
                    network_name = "NONAME"
            elif network_name and self.network_ids_by_normal_name.get(normalize_caseless(network_name)):
                network_id = self.network_ids_by_normal_name[normalize_caseless(network_name)]
        except Exception as e:
            raise RuntimeError(f"need one of network_id or network_name for a network in this network group: {self.name}, caught {e}")

        try:
            headers = {"authorization": "Bearer " + self.token}
            entity_url = self.audience+'core/v2/networks/'+network_id
            response = http.delete(
                entity_url,
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )
            response_code = response.status_code
            network = response.json()
        except Exception as e:
            raise RuntimeError(f"failed deleting network {entity_url} or loading JSON from response, caught {e}")

        if not response_code == STATUS_CODES.codes.ACCEPTED:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        return(network)
