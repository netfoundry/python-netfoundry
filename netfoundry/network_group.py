"""Use a network group and find its networks."""

from ast import Or
import json
import logging

from .utility import (NETWORK_RESOURCES, RESOURCES, STATUS_CODES,
                      find_resources, get_resource, http, is_uuidv4,
                      normalize_caseless)


class NetworkGroup:
    """use a network group by name or ID.
    
    The default is to use the first network group available to the organization of the caller.
    """

    def __init__(self, Organization: object, network_group_id: str=None, network_group_name: str=None, group: str=None):
        """Initialize the network group class with a group name or ID."""
        if (not network_group_id and not network_group_name) and group:
            if is_uuidv4(group):
                network_group_id = group
            else:
                network_group_name = group
        if network_group_id:
            self.network_group_id = network_group_id
            self.network_group_name = [ ng['organizationShortName'] for ng in Organization.network_groups if ng['id'] == network_group_id ][0]
        # TODO: review the use of org short name ref https://mattermost.tools.netfoundry.io/netfoundry/pl/gegyzuybypb9jxnrw1g1imjywh
        elif network_group_name:
            self.network_group_name = network_group_name
            network_group_matches = [ ng['id'] for ng in Organization.network_groups if ng['organizationShortName'] == network_group_name ]
            if len(network_group_matches) == 1:
                self.network_group_id = [ ng['id'] for ng in Organization.network_groups if ng['organizationShortName'] == network_group_name ][0]
            else:
                raise Exception("ERROR: there was not exactly one network group matching the name \"{}\"".format(network_group_name))
        elif len(Organization.network_groups) > 0:
            # first network group is typically the only network group
            self.network_group_id = Organization.network_groups[0]['id']
            self.network_group_name = Organization.network_groups[0]['organizationShortName']
            # warn if there are other groups
            if len(Organization.network_groups) > 1:
                logging.warn("using first network group {:s} and ignoring {:d} other(s) e.g. {:s}, etc...".format(
                    self.network_group_name,
                    len(Organization.network_groups) - 1,
                    Organization.network_groups[1]['organizationShortName']
                ))
            elif len(Organization.network_groups) == 1:
                logging.debug("using the only available network group: {:s}".format(
                    self.network_group_name
                ))
        else:
            raise Exception("need at least one network group in organization")

        self.session = Organization
        self.token = self.session.token
        self.proxies = self.session.proxies
        self.verify = self.session.verify
        self.audience = self.session.audience
        self.environment = self.session.environment
        self.describe = Organization.get_network_group(self.network_group_id)
        self.id = self.network_group_id
        self.name = self.network_group_name
        self.vanity = normalize_caseless(Organization.label)


        if self.environment == "production":
            self.nfconsole = "https://{vanity}.nfconsole.io".format(vanity=self.vanity)
        else:
            self.nfconsole = "https://{vanity}.{env}-nfconsole.io".format(vanity=self.vanity, env=self.environment)

    def nc_data_centers_by_location(self):
        """Get a controller data center by locationCode."""
        my_nc_data_centers_by_location = dict()
        for dc in self.get_controller_data_centers():
            my_nc_data_centers_by_location[dc['locationCode']] = dc['id']
            # e.g. { us-east-1: 02f0eb51-fb7a-4d2e-8463-32bd9f6fa4d7 }
        return(my_nc_data_centers_by_location)

    # resolve network UUIDs by name
    def networks_by_name(self):
        """Find networks in group by normalized name.
        
        Deprecated: use networks_by_normal_name
        """
        my_networks_by_name = dict()
        for net in self.session.get_networks_by_group(self.network_group_id):
            my_networks_by_name[net['name']] = net['id']
        return(my_networks_by_name)

    def networks_by_normal_name(self):
        """Find networks in group by case-insensitive (caseless, normalized) name.
        
        Case-insensitive uniqueness is enforced by the API for each type of entity.
        """
        my_networks_by_normal_name = dict()
        for name,id in self.networks_by_name().items():
            my_networks_by_normal_name[normalize_caseless(name)] = id
        return(my_networks_by_normal_name)

    def network_exists(self, name: str, deleted: bool=False):
        """Check if a network exists.
        
        :param name: the case-insensitive string to search
        :param deleted: include deleted networks in results
        """
        network_normal_names = list()
        for net in self.session.get_networks_by_group(network_group_id=self.network_group_id, deleted=deleted):
            network_normal_names.append(normalize_caseless(net['name']))
        if normalize_caseless(name) in network_normal_names:
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
        #params["provider"] = "AWS"

        url = self.audience+'core/v2/data-centers'
        headers = { "authorization": "Bearer " + self.token }
        try:
            data_centers = find_resources(url=url, headers=headers, embedded=NETWORK_RESOURCES['data-centers']._embedded, proxies=self.proxies, verify=self.verify, **params)
        except:
            logging.debug("failed to get data-centers from url: '%s'", url)
            raise
        else:
            return(data_centers)

    # provide a compatible alias
    get_controller_data_centers = nc_data_centers 

    def get_product_metadata(self, is_active: bool=True):
        """
        Get product version metadata.
        
        :param is_active: filter for only active product versions
        :param product_version: semver string of a single version to get, default is all versions
        """
        url = self.audience+'product-metadata/v2/download-urls.json'
        headers = dict() # no auth
        try:
            all_product_metadata = find_resources(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except:
            logging.debug("failed to get product-metadata from url: '%s'", url)
            raise
        else:
            if is_active:
                filtered_product_metadata = dict()
                for product in all_product_metadata.keys():
                    if all_product_metadata[product]['active']:
                        filtered_product_metadata[product] = all_product_metadata[product]
                return (filtered_product_metadata)
            else:
                return (all_product_metadata)

    def list_product_versions(self, product_metadata: dict=dict(), is_active: bool=True):
        """Find product versions in all products' metadata."""
        if product_metadata:
            product_versions = product_metadata.keys()
        else:
            product_metadata = self.get_product_metadata(is_active=is_active)
            product_versions = product_metadata.keys()

        return (product_versions)

    def find_latest_product_version(self, product_versions: list=list(), is_active: bool=True):
        """Get the highest product version number (may be experimental, not stable)."""
        if not product_versions:
            product_versions = self.list_product_versions(is_active=is_active)

        from distutils.version import LooseVersion
        return sorted(product_versions, key=LooseVersion)[-1]

    def create_network(self, name: str, network_group_id: str=None, location: str="us-east-1", version: str=None, size: str="small", **kwargs):
        """
        Create a network in this network group.

        :param name: required network name
        :param network_group: optional network group ID
        :param location: optional data center region name in which to create
        :param version: optional product version string like 7.3.17
        :param size: optional network configuration metadata name from /core/v2/network-configs e.g. "medium"
        """
        my_nc_data_centers_by_location = self.nc_data_centers_by_location()
        if not location in my_nc_data_centers_by_location.keys():
            raise Exception("ERROR: unexpected Network location '{:s}'. Valid locations include: {}.".format(location, my_nc_data_centers_by_location.keys()))

        # map incongruent api keys from kwargs to function params ("name", "size" are congruent)
        for param,value in kwargs.items():
            if param == 'networkGroupId':
                if network_group_id:
                    logging.debug("clobbering param 'network_group_id' with kwarg 'networkGroupId'")
                network_group_id = value
            elif param == 'locationCode':
                if location:
                    logging.debug("clobbering param 'location' with kwarg 'locationCode'")
                location = value
            elif param == 'productVersion':
                if version:
                    logging.debug("clobbering param 'version' with kwarg 'productVersion'")
                version == value
            else:
                logging.warn("ignoring unexpected keyword argument '%s'", param)

        request = {
            "name": name,
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
                pass # do not specify a value for productVersion
            else:
                raise Exception("ERROR: invalid version \"{version}\". Expected one of {product_versions}".format(
                    version=version,
                    product_versions=product_versions))

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
        except:
            raise

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, RESOURCES['networks'].create_responses):
            try:
                network = json.loads(response.text)
            except ValueError as e:
                raise e('ERROR: failed to load created network JSON, got HTTP code {:s} ({:d}) with body {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text)
                )
            else:
                return(network)
        else:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

    def delete_network(self, network_id=None, network_name=None):
        """
        Delete a network.

        :param id: optional network UUID to delete
        :param name: optional network name to delete
        """
        try:
            networks_by_name = self.networks_by_name()
            if network_id:
                network_name = next(name for name, uuid in networks_by_name.items() if uuid == network_id)
            elif network_name and network_name in networks_by_name.keys():
                network_id = networks_by_name[network_name]
        except:
            raise Exception("ERROR: need one of network_id or network_name for a Network in this network group: {:s}".format(self.name))

        try:
            headers = { "authorization": "Bearer " + self.token }
            entity_url = self.audience+'core/v2/networks/'+network_id
            response = http.delete(
                entity_url,
                proxies=self.proxies,
                verify=self.verify,
                headers=headers
            )
            response_code = response.status_code
        except:
            raise

        if not response_code == STATUS_CODES.codes.ACCEPTED:
            raise Exception(
                'ERROR: got unexpected HTTP code {:s} ({:d}) and response {:s}'.format(
                    STATUS_CODES._codes[response_code][0].upper(),
                    response_code,
                    response.text
                )
            )

        network = json.loads(response.text)
        return(network)

