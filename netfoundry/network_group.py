"""Use a network group and find its networks."""

from .network import Networks
from .utility import NET_RESOURCES, RESOURCES, STATUS_CODES, any_in, find_generic_resources, get_generic_resource, http, is_uuidv4, normalize_caseless, caseless_equal


class NetworkGroup:
    """use a network group by name or ID.

    The default is to use the first network group available to the organization of the caller.
    """

    def __init__(self, Organization: object, network_group_id: str = None, network_group_name: str = None, group: str = None):
        """Initialize the network group class with a group name or ID."""
        self.logger = Organization.logger
        self.Networks = Networks(Organization)
        self.network_groups = Organization.get_network_groups_by_organization()
        if (not network_group_id and not network_group_name) and group:
            if is_uuidv4(group):
                network_group_id = group
            else:
                network_group_name = normalize_caseless(group)
        if network_group_id:
            self.network_group_id = network_group_id
            self.network_group_name = [ng['organizationShortName'] for ng in self.network_groups if ng['id'] == network_group_id][0]
        # TODO: review the use of org short name ref https://mattermost.tools.netfoundry.io/netfoundry/pl/gegyzuybypb9jxnrw1g1imjywh
        elif network_group_name:
            self.network_group_name = network_group_name
            network_group_matches = [ng['id'] for ng in self.network_groups if caseless_equal(ng['organizationShortName'], self.network_group_name)]
            if len(network_group_matches) == 1:
                self.network_group_id = network_group_matches[0]
            else:
                raise RuntimeError(f"there was not exactly one network group matching the name '{network_group_name}'")
        elif len(self.network_groups) > 0:
            # first network group is typically the only network group
            self.network_group_id = self.network_groups[0]['id']
            self.network_group_name = normalize_caseless(self.network_groups[0]['organizationShortName'])
            # warn if there are other groups
            if len(self.network_groups) > 1:
                self.logger.warning(f"using first network group {self.network_group_name} and ignoring {len(self.network_groups) - 1} other(s) e.g. {self.network_groups[1]['organizationShortName']}, etc...")
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

    def nc_data_centers_by_location(self):
        """Get a controller data center by locationCode."""
        my_nc_data_centers_by_location = dict()
        for dc in self.get_controller_data_centers():
            my_nc_data_centers_by_location[dc['locationCode']] = dc['id']
            # e.g. { us-east-1: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }
        return(my_nc_data_centers_by_location)

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

    def nc_data_centers(self, **kwargs):
        """Find network controller data centers."""
        # data centers returns a list of dicts (data center objects)
        params = dict()
        for param in kwargs.keys():
            params[param] = kwargs[param]
        params["productVersion"] = self.find_latest_product_version(is_active=True)
        params["hostType"] = "NC"
        params["provider"] = "AWS"

        url = self.audience+'core/v2/data-centers'
        headers = {"authorization": "Bearer " + self.token}
        try:
            data_centers = list()
            for i in find_generic_resources(url=url, headers=headers, embedded=NET_RESOURCES['data-centers']._embedded, proxies=self.proxies, verify=self.verify, **params):
                data_centers.extend(i)
        except Exception as e:
            raise RuntimeError(f"failed to get data-centers from url: '{url}', caught {e}")
        else:
            return(data_centers)

    # provide a compatible alias
    get_controller_data_centers = nc_data_centers

    def get_product_metadata(self, is_active: bool = True):
        """
        Get product version metadata.

        :param is_active: filter for only active product versions
        :param product_version: semver string of a single version to get, default is all versions
        """
        url = self.audience+'product-metadata/v2/download-urls.json'
        headers = dict()  # no auth
        try:
            all_product_metadata, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get product-metadata from url: '{url}', caught {e}")
        else:
            if is_active:
                filtered_product_metadata = dict()
                for product in all_product_metadata.keys():
                    if all_product_metadata[product]['active']:
                        filtered_product_metadata[product] = all_product_metadata[product]
                return (filtered_product_metadata)
            else:
                return (all_product_metadata)

    def list_product_versions(self, product_metadata: dict = dict(), is_active: bool = True):
        """Find product versions in all products' metadata."""
        if product_metadata:
            product_versions = product_metadata.keys()
        else:
            product_metadata = self.get_product_metadata(is_active=is_active)
            product_versions = product_metadata.keys()

        return (product_versions)

    def find_latest_product_version(self, product_versions: list = list(), is_active: bool = True):
        """Get the highest product version number (may be experimental, not stable)."""
        if not product_versions:
            product_versions = self.list_product_versions(is_active=is_active)

        from distutils.version import LooseVersion
        return sorted(product_versions, key=LooseVersion)[-1]

    def create_network(self, name: str, network_group_id: str = None, location: str = "us-east-1", version: str = None, size: str = "small", wait: int = 0, sleep: int = 10, **kwargs):
        """
        Create a network in this network group.

        :param name: required network name
        :param network_group: optional network group ID
        :param location: optional data center region name in which to create
        :param version: optional product version string like 7.3.17
        :param size: optional network configuration metadata name from /core/v2/network-configs e.g. "medium"
        """
        my_nc_data_centers_by_location = self.nc_data_centers_by_location()
        if not my_nc_data_centers_by_location.get(location):
            raise RuntimeError(f"unexpected network location '{location}'. Valid locations include: {', '.join(my_nc_data_centers_by_location.keys())}.")

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

        request = {
            "name": name.strip('"'),
            "locationCode": location,
            "size": size,
        }

        if network_group_id:
            request["networkGroupId"] = network_group_id
        else:
            request["networkGroupId"] = self.network_group_id

        if version:
            product_versions = self.list_product_versions()
            if version == "latest":
                request['productVersion'] = self.find_latest_product_version(product_versions)
            elif version in product_versions:
                request['productVersion'] = version
            elif version == "default":
                pass    # do not specify a value for productVersion
            else:
                raise RuntimeError(f"invalid version '{version}'. Expected one of {product_versions}")
        headers = {
            'Content-Type': 'application/json',
            "authorization": "Bearer " + self.token
        }

        try:
            response = http.post(
                self.audience+"core/v2/networks",
                proxies=self.proxies,
                verify=self.verify,
                json=request,
                headers=headers
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"problem creating network, caught {e}")

        # the HTTP response code is one of the expected responses for creating a network
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['networks'].create_responses):
            resource = response.json()
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        if resource.get('_links') and resource['_links'].get('process-executions'):
            _links = resource['_links'].get('process-executions')
            if isinstance(_links, list):
                process_id = _links[0]['href'].split('/')[6]
            else:
                process_id = _links['href'].split('/')[6]
            if wait:
                self.Networks.wait_for_process(process_id, RESOURCES["process-executions"].status_symbols['complete'], wait=wait, sleep=sleep)
                resource = self.get_resource_by_id(type="network", id=resource['id'])
                return(resource)
            else:    # only wait for the process to start, not finish, or timeout
                # FIXME: commented to allow create to succeed to workaround MOP-18095
                # self.Networks.wait_for_process(process_id, RESOURCES['process-executions'].status_symbols['progress'] + RESOURCES['process-executions'].status_symbols['complete'], wait=9, sleep=3)
                return(resource)
        elif wait:
            self.logger.warning("unable to wait for async complete because response did not provide a process execution id")
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
