"""Use a network and find and manage its resources."""

import json
import logging
import re
import sys
import time

from .utility import (DC_PROVIDERS, MUTABLE_NETWORK_RESOURCES,
                      NETWORK_RESOURCES, RESOURCES, STATUS_CODES, VALID_SEPARATORS,
                      VALID_SERVICE_PROTOCOLS, docstring_parameters,
                      find_generic_resources, get_generic_resource, http, is_uuidv4, plural,
                      singular, normalize_caseless)


class Network:
    """Describe and use a network."""

    def __init__(self, NetworkGroup: object, network_id: str = None, network_name: str = None, network: str = None):
        """Initialize network.

        :param obj NetworkGroup: required parent network group of this network
        :param str network: optional identifier to resolve as UUID or name, ignored if network_id or network_name
        :param str network_name: optional name of the network to describe and use
        :param str network_id: optional UUID of the network to describe and use
        """
        # define some essential attributes
        self.token = NetworkGroup.token
        self.proxies = NetworkGroup.proxies
        self.verify = NetworkGroup.verify
        self.audience = NetworkGroup.audience
        self.network_group_id = NetworkGroup.id

        if (not network_id and not network_name) and network:
            if is_uuidv4(network):
                network_id = network
            else:
                network_name = network
        elif (network_id or network_name) and network:
            logging.warn(f"ignoring network identifier '{network}' because network_id or network_name were provided")

        if network_id:
            self.describe = self.get_network_by_id(network_id)
        elif network_name:
            self.describe = self.get_network_by_name(name=network_name)
        else:
            raise RuntimeError("need one of network_id or network_name")

        # define some convenience attributes
        self.id = self.describe['id']
        self.name = self.describe['name']
        self.status = self.describe['status']
        self.network_controller = self.describe['networkController']
        self.product_version = self.describe['productVersion']
        self.owner_identity_id = self.describe['ownerIdentityId']
        self.size = self.describe['size']
        self.o365_breakout_category = self.describe['o365BreakoutCategory']
        self.created_at = self.describe['createdAt']
        self.updated_at = self.describe['updatedAt']
        self.created_by = self.describe['createdBy']

    def endpoints(self, name: str = None, typeId: str = None):
        """Find endpoints.

        :param str typeId: optionally filter results by typeId e.g. "Device" or "Router"
        :param str name: optionally filter by case-insensitive name
        """
        if typeId is not None:
            return(self.get_resources(name=name, type="endpoints", typeId=typeId))
        else:
            return(self.get_resources(name=name, type="endpoints"))

    def endpoint_exists(self, name: str):
        """Check if endpoint exists.

        :param str name: case-insensitive display name to search.
        """
        return(self.resource_exists_in_network(name=name, type="endpoints"))

    def edge_routers(self, name: str = None, only_hosted: bool = False, only_customer: bool = False):
        """Find edge routers.

        :param bool only_customer: only find routers that are customer-hosted, ignoring netfoundry-hosted
        :param str name: optionally filter by case-insensitive name
        """
        all_edge_routers = self.get_resources(name=name, type="edge-routers")
        if only_hosted and only_customer:
            raise RuntimeError("specify only one of only_hosted or only_customer")
        elif only_hosted:
            hosted_edge_routers = [er for er in all_edge_routers if er.get('provider') and not er['provider'] == 'CUSTOMER']
            return(hosted_edge_routers)
        elif only_customer:
            customer_edge_routers = [er for er in all_edge_routers if not er.get('provider') or er['provider'] == 'CUSTOMER']
            return(customer_edge_routers)
        else:
            return(all_edge_routers)

    def edge_router_exists(self, name: str):
        """Check if edge router exists.

        :param str name: case-insensitive display name to search.
        """
        return(self.resource_exists_in_network(name=name, type="edge-routers"))

    def services(self, name: str = None):
        """Find services.

        :param str name: optionally filter by case-insensitive name
        """
        return(self.get_resources(name=name, type="services"))

    def service_exists(self, name: str):
        """Check if service exists.

        :param str name: case-insensitive display name to search.
        """
        return(self.resource_exists_in_network(name=name, type="services"))

    def edge_router_policies(self, name: str = None):
        """Find edge router policies.

        :param str name: optionally filter by case-insensitive name
        """
        return(self.get_resources(name=name, type="edge-router-policies"))

    def edge_router_policy_exists(self, name: str):
        """Check if edge router policy exists.

        :param str name: case-insensitive display name to search.
        """
        return(self.resource_exists_in_network(name=name, type="edge-router-policies"))

    def app_wans(self, name: str = None):
        """Find app-wans.

        :param str name: optionally filter by case-insensitive name
        """
        return(self.get_resources(name=name, type="app-wans"))

    def app_wan_exists(self, name: str):
        """Check if app wan exists.

        :param str name: case-insensitive display name to search.
        """
        return(self.resource_exists_in_network(name=name, type="app-wans"))

    def posture_checks(self, name: str = None):
        """Find posture checks.

        :param str name: optionally filter by case-insensitive name
        """
        return(self.get_resources(name=name, type="posture-checks"))

    def posture_check_exists(self, name: str):
        """Check if posture check exists.

        :param str name: case-insensitive display name to search.
        """
        return(self.resource_exists_in_network(name=name, type="posture-checks"))

    def delete_network(self, wait: int = 300, progress=False):
        """Delete the network for which this class instance was created."""
        self.delete_resource(type="network", wait=wait, progress=progress)

    def delete_endpoint(self, id: str, wait: int = 300, progress: bool = False):
        """Delete an endpoint by ID."""
        self.delete_resource(id=id, type="endpoint", wait=wait, progress=progress)

    def delete_service(self, id: str, wait: int = 300, progress: bool = False):
        """Delete a service by ID."""
        self.delete_resource(id=id, type="service", wait=wait, progress=progress)

    def delete_edge_router(self, id: str, wait: int = 300, progress: bool = False):
        """Delete an edge router by ID."""
        self.delete_resource(id=id, type="edge-router", wait=wait, progress=progress)

    def delete_edge_router_policy(self, id: str, wait: int = 300, progress: bool = False):
        """Delete an edge router policy by ID."""
        self.delete_resource(id=id, type="endpoint", wait=wait, progress=progress)

    def delete_app_wan(self, id: str, wait: int = 300, progress: bool = False):
        """Delete an app-wan by ID."""
        self.delete_resource(id=id, type="app-wan", wait=wait, progress=progress)

    def delete_service_policy(self, id: str, wait: int = 300, progress: bool = False):
        """Delete a service policy by ID."""
        self.delete_resource(id=id, type="service-policy", wait=wait, progress=progress)

    def delete_service_edge_router_policy(self, id: str, wait: int = 300, progress: bool = False):
        """Delete a service edge router policy by ID."""
        self.delete_resource(id=id, type="service-edge-router-policy", wait=wait, progress=progress)

    def delete_posture_check(self, id: str, wait: int = 300, progress: bool = False):
        """Delete a posture check by ID."""
        self.delete_resource(id=id, type="posture-check", wait=wait, progress=progress)

    @docstring_parameters(valid_separators=VALID_SEPARATORS)
    def validate_port_ranges(self, ports: list):
        """Return a validated list of low, high port ranges.

        The validated ranges will matching the expected format when supplied a list of candidate ports and ranges
        like [80, "8000:8002", "8443-8444"].
        :param list ports: required list of integers or strings that are each a single port (int or str) or low:high range of ports separated by a character matching regex /{valid_separators}
        """
        # these elements could be a single port as integer or a string with one or two ports separated by a valid separator character
        separators = re.compile(VALID_SEPARATORS)
        valid_range = re.compile(r'^\d+'+VALID_SEPARATORS+r'\d+$')
        valid_port_ranges = list()
        for range in ports:
            if isinstance(range, int):              # if an integer or single port then use same number for low:high
                range = str(range)+':'+str(range)
            elif not re.search(separators, range):  # if a string of a single port (no separator) then cat with separator :
                range = range+':'+range

            if not re.fullmatch(valid_range, range):
                raise RuntimeError(f"failed to parse client port range: {range}")

            bounds = re.split(separators, range)
            if not len(bounds) == 2 or int(bounds[0]) > int(bounds[1]):
                raise RuntimeError(f"failed to find one lower, one higher port for range: {range}")
            else:
                valid_port_ranges.append({"low": int(bounds[0]), "high": int(bounds[1])})

        return(valid_port_ranges)

    @docstring_parameters(resource_entity_types=str(NETWORK_RESOURCES.keys()))
    def validate_entity_roles(self, entities: list, type: str):
        """Return a list of valid, existing entities and hashtag role attributes.

        Input is a list of candidate hashtag role attributes or existing entity
        identitifiers and use the validated list anywhere that Ziti entity
        roles are used e.g. list of endpoints in an AppWAN, list of routers in
        an ERP.

        :param list entities: required hashtag role attributes, existing entity @names, or existing entity UUIDs
        :param str type: required type of entity, choices: {resource_entity_types}
        """
        valid_entities = list()
        for entity in entities:
            if entity[0:1] == '#':
                valid_entities.append(entity)  # is a hashtag role attribute
            else:
                # strip leading @ if present and re-add later after verifying the named entity exists
                if entity[0:1] == '@':
                    entity = entity[1:]

                # if UUIDv4 then resolve to name, else verify the named entity exists
                if is_uuidv4(entity):          # assigned below under "else" if already a UUID
                    try:
                        name_lookup = self.get_resource(type=singular(type), id=entity)
                        entity_name = name_lookup['name']
                    except Exception as e:
                        raise RuntimeError(f"failed to find exactly one {singular(type)} with ID '{entity}'. Caught exception: {e}")
                    else:
                        valid_entities.append('@'+entity_name)  # is an existing endpoint's name resolved from UUID
                else:
                    try:
                        name_lookup = self.get_resources(type=plural(type), name=entity)[0]
                        entity_name = name_lookup['name']
                    except Exception as e:
                        raise RuntimeError(f"failed to find exactly one {singular(type)} named '{entity}'. Caught exception: {e}")
                    # append to list after successfully resolving name to ID
                    else:
                        valid_entities.append('@'+entity_name)  # is an existing entity's name

        return(valid_entities)

    def get_data_center_by_id(self, id: str):
        """Get data centers by UUIDv4.

        :param id:        required UUIDv4 of data center
        """
        url = self.audience+'core/v2/data-centers/'+id
        headers = {"authorization": "Bearer " + self.token}
        try:
            data_center, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get data_center from url: '{url}', got {e}")
        else:
            return(data_center)

    @docstring_parameters(providers=str(DC_PROVIDERS))
    def get_edge_router_data_centers(self, provider: str = None, location_code: str = None, **kwargs):
        """Find data centers for hosting edge routers.

        :param provider:        optionally filter by data center provider, choices: {providers}
        :param location_code:   provider-specific string identifying the data center location e.g. us-west-1
        """
        params = dict()
        for param in kwargs.keys():
            params[param] = kwargs[param]
        params["productVersion"] = self.product_version
        params["hostType"] = "ER"
        if location_code:
            params["locationCode"] = location_code  # not yet implemented in API
        elif params.get('locationCode'):
            location_code = params['locationCode']
        if provider is not None:
            if provider in DC_PROVIDERS:
                params['provider'] = provider
            else:
                raise RuntimeError(f"unknown cloud provider '{provider}'. Need one of {str(DC_PROVIDERS)}")

        url = self.audience+'core/v2/data-centers'
        headers = {"authorization": "Bearer " + self.token}
        try:
            data_centers = list()
            for i in find_generic_resources(url=url, headers=headers, embedded=NETWORK_RESOURCES['data-centers']._embedded, proxies=self.proxies, verify=self.verify, **params):
                data_centers.extend(i)
        except Exception as e:
            raise RuntimeError(f"failed to get data-centers from url: '{url}', got {e}")
        else:
            if location_code:
                return [dc for dc in data_centers if dc['locationCode'] == location_code]
            else:
                return data_centers

    def share_endpoint(self, recipient, endpoint_id):
        """
        Share an endpoint's enrollment token with an email address.

            :recipient [required] the email address
            :endpoint_id [required] the UUID of the endpoint
        """
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            body = [
                {
                    "toList": [recipient],
                    "subject": "Your enrollment token for {:s}".format(self.name),
                    "id": endpoint_id
                }
            ]
            response = http.post(
                self.audience+'core/v2/endpoints/share',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error posting to share endpoint to email, got {e}")

        if not response_code == STATUS_CODES.codes['ACCEPTED']:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

    def get_resource_by_id(self, type: str, id: str, accept: str = None):
        """Return an object describing a resource entity.

        :param type: required string of the singular of an entity type e.g. network, endpoint, service, edge-router, edge-router-policy, posture-check
        :param id: the UUID of the entity if not a network
        :param: accept: optional modifier string specifying the form of the desired response. Choices ["create","update"] where
                "create" is useful for comparing an existing entity to a set of properties that are used to create the same type of
                entity in a POST request, and "update" may be used in the same way for a PUT update.
        """
        # to singular if plural
        if type[-1] == "s":
            type = singular(type)
        headers, params = dict(), dict()
        if accept:
            if accept in ["create", "update"]:
                headers['accept'] = "application/json;as="+accept
            else:
                logging.warn(f"ignoring invalid value for param 'accept': '{accept}'")
        if not type == "network":
            params["networkId"] = self.id
        if not NETWORK_RESOURCES.get(plural(type)):
            raise RuntimeError(f"unknown resource type '{plural(type)}'. Choices: {','.join(NETWORK_RESOURCES.keys())}")
        elif plural(type) in ["edge-routers", "network-controllers"]:
            params['embed'] = "host"

        headers = {"authorization": "Bearer " + self.token}
        url = self.audience+'core/v2/'+plural(type)+'/'+id
        try:
            resource, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get resource from url: '{url}', got {e}")
        else:
            return(resource)
    get_resource = get_resource_by_id

    def get_resources(self, type: str, accept: str = None, deleted: bool = False, **kwargs):
        """Find resources by type.

        :param str type: plural of an entity type in the network domain e.g. networks, endpoints, services, posture-checks, etc...
        :param str kwargs: filter results by logical AND query parameters
        :param str accept: specifying the form of the desired response. Choices ["create","update"] where
                "create" is useful for comparing an existing entity to a set of properties that are used to create the same type of
                entity in a POST request, and "update" may be used in the same way for a PUT update.
        :param bool deleted: include resource entities that have a non-null property deletedAt
        """
        # pluralize if singular
        if not type[-1] == "s":
            type = plural(type)
        if type == "data-centers":
            logging.warn("don't call network.get_resources() for data centers, always use network.get_edge_router_data_centers() to filter for locations that support this network's version")

        params = dict()
        for param in kwargs.keys():
            params[param] = kwargs[param]
        if not plural(type) == 'networks':
            params["networkId"] = self.id
        elif params.get('name'):
            params['findByName'] = params['name']
            del params['name']
        if deleted:
            params['status'] = "DELETED"

        url = self.audience+'core/v2/'+plural(type)
        headers = {"authorization": "Bearer " + self.token}
        try:
            resources = list()
            for i in find_generic_resources(url=url, headers=headers, embedded=NETWORK_RESOURCES[type]._embedded, accept=accept, proxies=self.proxies, verify=self.verify, **params):
                resources.extend(i)
        except Exception as e:
            raise RuntimeError(f"failed to get {plural(type)} from url: '{url}', got {e}")
        else:
            return(resources)

    def resource_exists_in_network(self, name: str, type: str, deleted: bool = False):
        """Check if a resource of a particular type with a particular name exists in this network.

        :param str name: the case-insensitive name to search
        :param str type: plural of an entity type e.g. networks, endpoints, services, posture-checks, etc...
        :param bool deleted: search deleted resources
        """
        normal_names = list()
        for normal in self.get_resources(name=name, type=type, deleted=deleted):
            normal_names.append(normalize_caseless(normal['name']))
        if normalize_caseless(name) in normal_names:
            return(True)
        else:
            return(False)

    def patch_resource(self, patch: dict, type: str = None, id: str = None, wait: int = 0, sleep: int = 2, progress: bool = False):
        """Diff existing and expected properties and send a patch request with changed values.

        Returns the response object for the patched entity if at least one change, else the existing entity.
            :patch: required dictionary with changed properties and _links.self.href
            :param type: optional entity type, needed if put object lacks a self link, ignored if self link present
            :param id: optional entity ID, needed if put object lacks a self link, ignored if self link present
        """
        headers = {"authorization": "Bearer " + self.token}

        # prefer the self link if present, else require type and id to compose the self link
        try:
            self_link = patch['_links']['self']['href']
        except KeyError:
            try:
                self_link = self.audience+'core/v2/'+plural(type)+'/'+id
            except NameError as e:
                raise RuntimeError(f"error composing URL to patch resource, got {e}")
        else:
            type = self_link.split('/')[5]           # e.g. endpoints, app-wans, edge-routers, etc...

        if not MUTABLE_NETWORK_RESOURCES.get(type):  # prune properties that can't be patched
            raise RuntimeError(f"got unexpected type {type} for patch request to {self_link}")
        try:
            before_resource, status_symbol = get_generic_resource(url=self_link, headers=headers, proxies=self.proxies, verify=self.verify, accept='update')
        except Exception as e:
            raise RuntimeError(f"failed to get {type} for patching: '{e}'")
        else:
            # compare the patch to the discovered, current state, adding new or updated keys to pruned_patch
            pruned_patch = dict()
            for k in patch.keys():
                if k not in RESOURCES[type].no_update_props and before_resource.get(k):
                    if isinstance(patch[k], list):
                        if not set(before_resource[k]) == set(patch[k]):
                            pruned_patch[k] = list(set(patch[k]))
                    else:
                        if not before_resource[k] == patch[k]:
                            pruned_patch[k] = patch[k]

            # attempt to update if there's at least one difference between the current resource and the submitted patch
            if len(pruned_patch.keys()) > 0:
                if not pruned_patch.get('name'):
                    pruned_patch["name"] = before_resource["name"]
                # if entity is a service and "model" is patched then always include "modelType"
                if type == "services" and not pruned_patch.get('modelType') and pruned_patch.get('model'):
                    pruned_patch["modelType"] = before_resource["modelType"]
                try:
                    after_response = http.patch(
                        self_link,
                        proxies=self.proxies,
                        verify=self.verify,
                        headers=headers,
                        json=pruned_patch
                    )
                    after_response_code = after_response.status_code
                except Exception as e:
                    raise RuntimeError(f"error with PATCH request to {self_link}, got {e}")
                if after_response_code in [STATUS_CODES.codes.OK, STATUS_CODES.codes.ACCEPTED]:  # HTTP 202
                    try:
                        after_resource = after_response.json()
                    except ValueError as e:
                        raise RuntimeError(f"failed to load {type} object from PATCH response, got {e}")
                else:
                    raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[after_response_code][0].upper()} ({after_response_code}) for patch: {json.dumps(patch, indent=2)}")

                # if API responded with async promise then parse the expected process execution ID
                if wait and after_response_code == STATUS_CODES.codes.ACCEPTED:                  # HTTP 202
                    # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
                    process_id = after_resource['_links']['process']['href'].split('/')[6]

                    # monitor async process
                    if wait:
                        try:
                            self.wait_for_status(expect="FINISHED", type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
                        except Exception as e:
                            raise RuntimeError(f"timed out waiting for process status 'FINISHED', got {e}")
                        try:
                            # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                            #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                            finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type=type,
                                                                      id=after_resource['id'], wait=3, sleep=1)
                        except Exception as e:
                            raise RuntimeError(f"timed out waiting for property 'zitiId' to be defined, got {e}")
                        return(finished)
                    else:  # if not wait then merely verify the async process was at least started if not finished
                        try:
                            self.wait_for_statuses(expected_statuses=["STARTED", "FINISHED"], type="process", id=process_id, wait=5, sleep=2, progress=progress)
                        except Exception as e:
                            raise RuntimeError(f"timed out waiting for process status 'STARTED' or 'FINISHED', got {e}")
                return(after_resource)
            else:
                # no change, return the existing unmodified entity
                return(before_resource)

    def put_resource(self, put: dict, type: str = None, id: str = None, wait: int = 0, sleep: int = 2, progress: bool = False):
        """Update a resource with a complete set of properties.

        Blindly updates the entity in self link and returns the response object.
            :param put: required dictionary with all properties required by the particular resource type's model
            :param type: optional entity type, needed if put object lacks a self link, ignored if self link present
            :param id: optional entity ID, needed if put object lacks a self link and id property, ignored if self link present
        """
        # prefer the self link if present, else require type and id to compose the self link
        try:
            self_link = put['_links']['self']['href']
        except KeyError:
            if not type:
                logging.error('need put object with "self" link or need type param')
                raise Exception('need put object with "self" link or need type param')
            if not id:
                if put.get('id'):
                    id = put['id']
                    logging.debug(f"got id '{id}' from put param object")
                else:
                    logging.error('missing id of {type} to update, need put object with "self" link, "id" property, or need "id" param'.format(type=type))
                    raise Exception('missing id of {type} to update, need put object with "self" link, "id" property, or need "id" param'.format(type=type))
            try:
                self_link = self.audience+'core/v2/'+plural(type)+'/'+id
            except NameError as e:
                raise(e)
        else:
            type = self_link.split('/')[5]  # e.g. endpoints, app-wans, edge-routers, etc...
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            response = http.put(
                self_link,
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=put
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with PUT to {self_link}, got {e}")

        if response_code in [STATUS_CODES.codes.OK, STATUS_CODES.codes.ACCEPTED]:  # HTTP 202
            try:
                resource = response.json()
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) for put: {json.dumps(put, indent=2)}")

        # if API responded with async promise then parse the expected process execution ID, error if missing
        if wait and response_code == STATUS_CODES.codes.ACCEPTED:  # HTTP 202
            # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
            process_id = resource['_links']['process']['href'].split('/')[6]

            # monitor async process, moot if API responded OK because this implies synchronous fulfillment of request
            if wait:
                try:
                    self.wait_for_status(expect="FINISHED", type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
                except RuntimeError as e:
                    raise RuntimeError(f"error while waiting for process status 'FINISHED', got {e}")
                try:
                    # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                    #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                    finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type=type,
                                                              id=resource['id'], wait=3, sleep=1)
                except Exception as e:
                    raise RuntimeError(f"error waiting for property 'zitiId' to be defined, got {e}")
                return(finished)
            else:   # if not wait then merely verify the async process was at least started if not finished
                try:
                    self.wait_for_statuses(expected_statuses=["STARTED", "FINISHED"], type="process", id=process_id, wait=5, sleep=2, progress=progress)
                except Exception as e:
                    raise RuntimeError(f"error waiting for process status 'STARTED' or 'FINISHED', got {e}")

        return(resource)

    def create_resource(self, type: str, post: dict, wait: int = 30, sleep: int = 2, progress: bool = False):
        """
        Create a raw resource by sending a complete set of properties for some type of entity.

        :param type: entity type such as endpoint, service, edge-router, app-wan
        :param post: required dictionary with all properties required by the particular resource type's model
        """
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            post['networkId'] = self.id
            if post.get('name'):
                post['name'] = post['name'].strip('"')
            response = http.post(
                self.audience+'core/v2/'+plural(type),
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=post
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error POST to {self.audience+'core/v2/'+plural(type)}, got {e}")

        if response_code in [STATUS_CODES.codes.OK, STATUS_CODES.codes.ACCEPTED]:  # HTTP 202
            try:
                resource = response.json()
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) for post: {json.dumps(post, indent=2)}")

        # if API responded with async promise then parse the expected process execution ID, error if missing
        if response_code == STATUS_CODES.codes.ACCEPTED:                           # HTTP 202
            # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
            process_id = resource['_links']['process']['href'].split('/')[6]

            # monitor async process, moot if API responded OK because this implies synchronous fulfillment of request
            if wait:
                try:
                    self.wait_for_status(expect="FINISHED", type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
                except Exception as e:
                    raise Exception("ERROR: timed out waiting for process status 'FINISHED'")
                try:
                    # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                    #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                    finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type=type,
                                                                id=resource['id'], wait=3, sleep=1)
                except Exception as e:
                    raise Exception("ERROR: timed out waiting for property 'zitiId' to be defined")
                return(finished)
            else: # if not wait then merely verify the async process was at least started if not finished
                try:
                    self.wait_for_statuses(expected_statuses=["STARTED","FINISHED"],type="process", id=process_id, wait=5, sleep=2, progress=progress)
                except Exception as e:
                    raise Exception("ERROR: timed out waiting for process status 'STARTED' or 'FINISHED'")

        return(resource)

    def create_endpoint(self, name: str, attributes: list=[], session_identity: str = None, wait: int = 30, sleep: int = 2, progress: bool = False):
        """Create an endpoint.

        :param: name is required string on which to key future operations for this endpoint
        :param: attributes is an optional list of endpoint roles of which this endpoint is a member
        :param: session_identity is optional string UUID of the identity in the NF organization for
                which a concurrent web console session is required to activate this endpoint
        """
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception("ERROR: hashtag role attributes on an endpoint must begin with #")
            body = {
                "networkId": self.id,
                "name": name.strip('"'),
                "attributes": attributes,
                "enrollmentMethod": { "ott": True }
            }

            if session_identity:
                body['sessionIdentityId'] = session_identity

            response = http.post(
                self.audience+'core/v2/endpoints',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/endpoints'}, got {e}")

        started = None
        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, NETWORK_RESOURCES['endpoints'].create_responses):
            try:
                started = response.json()
            except ValueError as e:
                raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response '{response.text}'")

        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}")

        # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
        process_id = started['_links']['process']['href'].split('/')[6]

        # a non-zero integer value for 'wait' guarantees that the method returns the fully-provisioned entity's object or times out
        #  with an exception, and a zero value guarantees only that the async create process started successfully within a short time
        # frame
        if wait:
            try:
                self.wait_for_status(expect="FINISHED",type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'FINISHED'")
            try:
                # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="endpoint",
                                                            id=started['id'], wait=3, sleep=1)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for property 'zitiId' to be defined")
            return(finished)
        else:
            try:
                self.wait_for_statuses(expected_statuses=["STARTED","FINISHED"],type="process", id=process_id, wait=5, sleep=2, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'STARTED' or 'FINISHED'")
            return(started)

    @docstring_parameters(providers=str(DC_PROVIDERS))
    def create_edge_router(self, name: str, attributes: list=[], link_listener: bool = False, data_center_id: str = None,
                            tunneler_enabled: bool = False, wait: int = 900, sleep: int = 10, progress: bool = False,
                            provider: str = None, location_code: str = None):
        """Create an edge router.

        A router may be hosted by NetFoundry or the customer. If hosted by NF,
        then you must supply datacenter "provider" and "location_code". If
        neither are given then the router is customer hosted.

        :param name:              a meaningful, unique name
        :param attributes:        a list of hashtag role attributes
        :param link_listener:     true if router should listen for other routers' transit links on 80/tcp, always true if hosted by NetFoundry
        :param data_center_id:    (DEPRECATED by provider, location_code) the UUIDv4 of a NetFoundry data center location that can host edge routers
        :param provider:          datacenter provider, choices: {providers}
        :param location_code:     provider-specific string identifying the datacenter location e.g. us-west-1
        :param tunneler_enabled:  true if the built-in tunneler features should be enabled for hosting or interception or both
        :param wait:              seconds to wait for async create to succeed
        """
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception("ERROR: hashtag role attributes on an endpoint must begin with #")
            body = {
                "networkId": self.id,
                "name": name.strip('"'),
                "attributes": attributes,
                "linkListener": link_listener,
                "tunnelerEnabled": tunneler_enabled
            }
            if data_center_id:
                logging.warning('data_center_id is deprecated by provider, location_code. ')
                data_center = self.get_data_center_by_id(id=data_center_id)
                body['provider'] = data_center['provider']
                body['locationCode'] = data_center['locationCode']
                body['linkListener'] = True
            elif provider or location_code:
                if provider and location_code:
                    data_centers = self.get_edge_router_data_centers(provider=provider, location_code=location_code)
                    if len(data_centers) == 1:
                        body['provider'] = provider
                        body['locationCode'] = location_code
                        body['linkListener'] = True
                    else:
                        raise Exception("ERROR: failed to find exactly one {provider} data center with location_code={location_code}".format(
                            provider=provider,
                            location_code=location_code))
                else:
                    raise Exception("ERROR: need both provider and location_code to create a hosted router.")

            response = http.post(
                self.audience+'core/v2/edge-routers',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/edge-routers'}, got {e}")
        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, NETWORK_RESOURCES['edge-routers'].create_responses):
            try:
                started = json.loads(response.text)
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
            else:
                if response.headers._store.get('x-b3-traceid'):
                    logging.debug(f"created edge router trace ID {response.headers._store['x-b3-traceid'][1]}'")
                else:
                    logging.debug(f"created edge router'")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
        process_id = started['_links']['process']['href'].split('/')[6]

        # a non-zero integer value for 'wait' guarantees that the method returns the fully-provisioned entity's object or times out
        #  with an exception, and a zero value guarantees only that the async create process started successfully within a short time
        # frame
        if wait:
            try:
                self.wait_for_status(expect="FINISHED",type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'FINISHED'")
            try:
                # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="edge-router",
                                                            id=started['id'], wait=3, sleep=1)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for property 'zitiId' to be defined")
            if tunneler_enabled:
                router_endpoint = self.wait_for_entity_name_exists(entity_name=name, entity_type="endpoint", wait=wait)
            return(finished)
        else:
            try:
                self.wait_for_statuses(expected_statuses=["STARTED","FINISHED"],type="process", id=process_id, wait=5, sleep=2, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'STARTED' or 'FINISHED'")
            return(started)

    def create_edge_router_policy(self, name: str, endpoint_attributes: list=[], edge_router_attributes: list=[], wait: int=30):
        """Create an edge router Policy.

        :param name:                    a meaningful, unique name
        :param endpoint_attributes:     a list of endpoint hashtag role attributes and endpoint name mentions
        :param edge_router_attributes:  a list of router hashtag role attributes and router name mentions
        :param wait:                    seconds to  wait for provisioning to finish before raising an exception
        """
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            for role in endpoint_attributes+edge_router_attributes:
                if not re.match('^[#@]', role):
                    raise Exception("ERROR: role attributes on a policy must begin with # or @")
            body = {
                "networkId": self.id,
                "name": name.strip('"'),
                "endpointAttributes": endpoint_attributes,
                "edgeRouterAttributes": edge_router_attributes
            }
            response = http.post(
                self.audience+'core/v2/edge-router-policies',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/edge-router-policies'}, got {e}")
        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, NETWORK_RESOURCES['edge-router-policies'].create_responses):
            try:
                started = response.json()
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        # ERPs are created in a blocking, synchronous manner, and so zitiId should be defined
        if wait and not started['zitiId']:
            finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="edge-router-policy", id=started['id'], wait=wait)
            return(finished)
        else:
            return(started)

    @docstring_parameters(valid_service_protocols=VALID_SERVICE_PROTOCOLS)
    def create_service_simple(self, name: str, client_host_name: str, client_port: int, server_host_name: str = None,
        server_port: int = None, server_protocol: str = "tcp", attributes: list = [], edge_router_attributes: list = ["#all"],
        egress_router_id: str = None, endpoints: list = [], encryption_required: bool = True, wait: int = 60, sleep: int = 3, progress: bool = False):
        """Create a service that is compatible with broadly-compatible Ziti config types ziti-tunneler-client.v1, ziti-tunneler-server.v1.

        There are three hosting strategies for a service: SDK, tunneler, or router.

        If server details are absent then the type is inferred to be SDK (service is hosted by a Ziti SDK,
        not a tunneler or router). If server details are present then the service is either hosted by a
        tunneler or router, depending on which value is present i.e. tunneler endpoint or edge router.

        Multiple client intercepts may be specified i.e. lists of domain names or IP addresses, ports, and protocols. If alternative
        server details are not given they are assumed to be the same as the intercept. If server details are provided then all intercepts
        flow to that server.

        :param: name is required string
        :param: client_host_name is required strings that is the intercept hostname (DNS) or IPv4
        :param: client_port is required integer of the ports to intercept
        :param: server_host_name is optional string that is a hostname (DNS) or IPv4. If omitted service is assumed to be SDK-hosted (not tunneler or router-hosted).
        :param: server_port is optional integer of the server port. If omitted the client port is used unless SDK-hosted.
        :param: server_protocol is optional string of the server protocol, choices: {valid_service_protocols}. Default is ["tcp"].
        :param: attributes is optional list of strings of service roles to assign. Default is [].
        :param: edge_router_attributes is optional list of strings of router roles or router names that can "see" this service. Default is ["#all"].
        :param: egress_router_id is optional string of UUID or name of hosting router. Selects router-hosting strategy.
        :param: endpoints is optional list of strings of hosting endpoints. Selects endpoint-hosting strategy.
        :param: encryption_required is optional Boolean. Default is to enable edge-to-edge encryption.
        """
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception(f'invalid role "{role}". Must begin with "#"')
            body = {
                "networkId": self.id,
                "name": name.strip('"'),
                "encryptionRequired": encryption_required,
                "model": {
                    "clientIngress" : {
                        "host": client_host_name,
                        "port": client_port,
                    },
                    "edgeRouterAttributes" : edge_router_attributes
                },
                "attributes" : attributes,
            }
            # resolve exit hosting params
            if not server_host_name:
                body['modelType'] = "TunnelerToSdk"
                if server_port:
                    logging.warning("ignoring unexpected server details for SDK-hosted service")
            else:
                server_egress = {
                    "protocol": server_protocol.lower(),
                    "host": server_host_name,
                    "port": server_port if server_port else client_port
                }
                if endpoints and not egress_router_id:
                    body['modelType'] = "TunnelerToEndpoint"
                    body['model']['serverEgress'] = server_egress
                elif egress_router_id and not endpoints:
                    body['modelType'] = "TunnelerToEdgeRouter"
                    # check if UUIDv4
                    if not is_uuidv4(egress_router_id):
                        # else assume is a name and resolve to ID
                        try:
                            name_lookup = self.get_resources(type="edge-routers",name=egress_router_id)[0]
                            egress_router_id = name_lookup['id'] # clobber the name value with the looked-up UUID
                        except Exception as e:
                            raise Exception('ERROR: Failed to find exactly one egress router "{}". Caught exception: {}'.format(egress_router_id, e))
                    body['model']['edgeRouterHosts'] = [{
                            "edgeRouterId": egress_router_id,
                            "serverEgress": server_egress,
                        }]
                else:
                    raise Exception('ERROR: invalid service model: need only one of binding "endpoints" or hosting "egress_router_id" if "server_host_name" is specified')

            # resolve edge router param
            if edge_router_attributes and not edge_router_attributes == ['#all']:
                logging.warning("overriding default service edge router Policy #all for new service {:s}".format(name))
                body['edgeRouterAttributes'] = edge_router_attributes

            if body['modelType'] in ["TunnelerToSdk","TunnelerToEndpoint"]:
                # parse out the elements in the list of endpoints as one of #attribute, UUID, or resolvable Endoint name
                bind_endpoints = list()
                for endpoint in endpoints:
                    if endpoint[0:1] == '#':
                        bind_endpoints += [endpoint]
                    else:
                        # strip leading @ if present and re-add later after verifying the named endpoint exists
                        if endpoint[0:1] == '@':
                            endpoint = endpoint[1:]

                        # if UUIDv4 then resolve to name, else verify the named endpoint exists
                        if is_uuidv4(endpoint): # assigned below under "else" if already a UUID
                            try:
                                name_lookup = self.get_resource(type="endpoint",id=endpoint)
                                endpoint_name = name_lookup['name']
                            except Exception as e:
                                raise Exception('ERROR: Failed to find exactly one hosting endpoint with ID "{}". Caught exception: {}'.format(endpoint, e))
                            else: bind_endpoints += ['@'+endpoint_name]
                        else:
                            # else assume is a name and resolve to ID
                            try:
                                name_lookup = self.get_resources(type="endpoints",name=endpoint)[0]
                                endpoint_name = name_lookup['name']
                            except Exception as e:
                                raise Exception('ERROR: Failed to find exactly one hosting endpoint named "{}". Caught exception: {}'.format(endpoint, e))
                            # append to list after successfully resolving name to ID
                            else: bind_endpoints += ['@'+endpoint_name]
                body['model']['bindEndpointAttributes'] = bind_endpoints

            params = dict()
            # params = {
            #     "beta": ''
            # }

            response = http.post(
                self.audience+'core/v2/services',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body,
                params=params
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/services'}, got {e}")
        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, NETWORK_RESOURCES['services'].create_responses):
            try:
                started = response.json()
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
        process_id = started['_links']['process']['href'].split('/')[6]

        # a non-zero integer value for 'wait' guarantees that the method returns the fully-provisioned entity's object or times out
        #  with an exception, and a zero value guarantees only that the async create process started successfully within a short time
        # frame
        if wait:
            try:
                self.wait_for_status(expect="FINISHED",type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'FINISHED'")
            try:
                # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service",
                                                            id=started['id'], wait=3, sleep=1)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for property 'zitiId' to be defined")
            return(finished)
        else:
            try:
                self.wait_for_statuses(expected_statuses=["STARTED","FINISHED"],type="process", id=process_id, wait=5, sleep=2, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'STARTED' or 'FINISHED'")
            return(started)

    # the above method was renamed to follow the development of PSM-based services (platform service models)
    create_service = create_service_simple

    def create_service_policy(self, name: str, services: list, endpoints: list, type: str = "Bind", semantic: str = "AnyOf",
                                posture_checks: list = [], dry_run: bool = False, wait: int = 30, sleep: int = 10, progress: bool = False):
        """
        Create a generic Ziti service policy. AppWANs are Dial-type service policies.

        :param str name: display name of service policy
        :param list services: service @names, UUIDs, or #hashtag service attributes
        :param list endpoints: endpoint @names, UUIDs, or #hashtag endpoint attributes
        :param str type: the policy type, one of Bind, Dial. Default is "Bind".
        :param str semantic: policy semantic, one of AnyOf, AllOf. Default is "AnyOf".
        :param list posture_checks: posture check @names, UUIDs, or #hashtag posture check attributes
        :param bool dry_run: True returns only the entity model without sending a request.
        """
        # parse out the elements in the list of endpoints as one of #attribute, UUID, or resolvable Endoint name
        bind_endpoints = self.validate_entity_roles(endpoints, type="endpoints")
        valid_services = self.validate_entity_roles(services, type="services")
        valid_postures = self.validate_entity_roles(posture_checks, type="posture-checks")
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            body = {
                "networkId": self.id,
                "name":  name.strip('"'),
                "type": type,
                "semantic": semantic,
                "postureCheckAttributes": valid_postures,
                "serviceAttributes": valid_services,
                "endpointAttributes": bind_endpoints
            }

            params = dict()
            # params = {
            #     "beta": ''
            # }

            if dry_run:
                return(body)

            response = http.post(
                self.audience+'core/v2/service-policies',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body,
                params=params
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/service-policies'}, got {e}")

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, NETWORK_RESOURCES['service-policies'].create_responses):
            try:
                started = response.json()
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
        process_id = started['_links']['process']['href'].split('/')[6]

        # a non-zero integer value for 'wait' guarantees that the method returns the fully-provisioned entity's object or times out
        #  with an exception, and a zero value guarantees only that the async create process started successfully within a short time
        # frame
        if wait:
            try:
                self.wait_for_status(expect="FINISHED",type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'FINISHED'")
            try:
                # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service-policy",
                                                            id=started['id'], wait=3, sleep=1)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for property 'zitiId' to be defined")
            return(finished)
        else:
            try:
                self.wait_for_statuses(expected_statuses=["STARTED","FINISHED"],type="process", id=process_id, wait=5, sleep=2, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'STARTED' or 'FINISHED'")
            return(started)


    def create_service_edge_router_policy(self, name: str, services: list, edge_routers: list, semantic: str="AnyOf",
                                            dry_run: bool=False, wait: int=30, sleep: int=10, progress: bool=False):
        """
        Create a generic Ziti service edge router policy (SERP). Model-based services auto-create a SERP.

        :param str name: display name of service policy
        :param list services: service @names, UUIDs, or #hashtag service attributes
        :param list edge_routers: router @names, UUIDs, or #hashtag router attributes
        :param str semantic: policy semantic, one of AnyOf, AllOf. Default is "AnyOf".
        :param bool dry_run: True returns only the entity model without sending a request.
        """
        valid_services = self.validate_entity_roles(services, type="services")
        valid_routers = self.validate_entity_roles(edge_routers, type="edge-routers")
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            body = {
                "networkId": self.id,
                "name":  name.strip('"'),
                "semantic": semantic,
                "serviceAttributes": valid_services,
                "edgeRouterAttributes": valid_routers
            }

            params = dict()
            # params = {
            #     "beta": ''
            # }

            if dry_run:
                return(body)

            response = http.post(
                self.audience+'core/v2/service-edge-router-policies',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body,
                params=params
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/service-edge-router-policies'}, got {e}")

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, NETWORK_RESOURCES['service-edge-router-policies'].create_responses):
            try:
                started = response.json()
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
        process_id = started['_links']['process']['href'].split('/')[6]

        # a non-zero integer value for 'wait' guarantees that the method returns the fully-provisioned entity's object or times out
        #  with an exception, and a zero value guarantees only that the async create process started successfully within a short time
        # frame
        if wait:
            try:
                self.wait_for_status(expect="FINISHED",type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'FINISHED'")
            try:
                # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service-edge-router-policy",
                                                            id=started['id'], wait=3, sleep=1)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for property 'zitiId' to be defined")
            return(finished)
        else:
            try:
                self.wait_for_statuses(expected_statuses=["STARTED","FINISHED"],type="process", id=process_id, wait=5, sleep=2, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'STARTED' or 'FINISHED'")
            return(started)

    def create_service_with_configs(self, name: str, intercept_config_data: dict, host_config_data: dict, attributes: list=[],
        encryption_required: bool=True, dry_run: bool=False, wait: int=60, sleep: int=10, progress: bool=False):
        """Create an endpoint-hosted service by providing the raw config data for intercept.v1, host.v1.

        :param: name is required string
        :param: intercept_config_data is a required dict that is the value of the 'data' property for the intercept.v1 config
        :param: host_config_data is a required dict that is the value of the 'data' property for the host.v1 config
        :param: attributes is optional list of strings of service roles to assign, associating the service with a matching AppWAN. Default is [].
        :param: encryption_required is optional Boolean. Default is to enable edge-to-edge encryption.
        :param: dry_run is optional Boolean where True returns only the entity model without sending a request.
        """
        try:
            # validate roles
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception('ERROR: invalid role "{:s}". Must begin with "#"'.format(role))

            headers = {
                "authorization": "Bearer " + self.token
            }
            body = {
                "networkId": self.id,
                "name": name.strip('"'),
                "encryptionRequired": encryption_required,
                "configs": [
                    {
                        "networkId": self.id,
                        "name": name+"-config-intercept.v1",
                        "configTypeName": "intercept.v1",
                        "data": intercept_config_data
                    },
                    {
                        "networkId": self.id,
                        "name": name+"-config-host.v1",
                        "configTypeName": "host.v1",
                        "data": host_config_data
                    }
                ],
                "attributes" : attributes,
            }

            params = dict()
            # params = {
            #     "beta": ''
            # }

            if dry_run:
                return(body)

            response = http.post(
                self.audience+'core/v2/services',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body,
                params=params
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/services'}, got {e}")

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, NETWORK_RESOURCES['services'].create_responses):
            try:
                started = response.json()
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
        process_id = started['_links']['process']['href'].split('/')[6]

        # a non-zero integer value for 'wait' guarantees that the method returns the fully-provisioned entity's object or times out
        #  with an exception, and a zero value guarantees only that the async create process started successfully within a short time
        # frame
        if wait:
            try:
                self.wait_for_status(expect="FINISHED",type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'FINISHED'")
            try:
                # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service",
                                                            id=started['id'], wait=3, sleep=1)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for property 'zitiId' to be defined")
            return(finished)
        else:
            try:
                self.wait_for_statuses(expected_statuses=["STARTED","FINISHED"],type="process", id=process_id, wait=5, sleep=2, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'STARTED' or 'FINISHED'")
            return(started)

    @docstring_parameters(valid_service_protocols=VALID_SERVICE_PROTOCOLS)
    def create_service_transparent(self, name: str, client_hosts: list, client_ports: list, transparent_hosts: list, client_protocols: list = ["tcp"], attributes: list = [],
        endpoints: list = [], edge_routers: list = ["#all"], encryption_required: bool = True, dry_run: bool = False):
        """Create an endpoint-hosted service where intercepted packets' source and destination are preserved by the terminator when communicating with the server at egress.

        :param str name: name of service
        :param list client_hosts: IPv4/CIDR to intercept.
        :param list client_ports: ports and ranges to intercept as singleton (int or str) or range [22, "80","5900:5999"].
        :param list transparent_hosts: allowed source IPs for terminator to use when masquerading to the server.
        :param list client_protocols: transports to intercept. Choices: {valid_service_protocols}. Default is ["tcp"].
        :param list attributes: service roles to assign, associating the service with a matching AppWAN or service policy. Default is [].
        :param list endpoints: endpoint #hashtag role attributes, @names, and UUIDs that may host this service.
        :param: list edge_routers: edge router #hashtag role attributes, @names, and UUIDs that can "see" this service. Default is ["#all"].
        :param bool encryption_required: Default is to enable edge-to-edge encryption.
        :param bool dry_run: True returns only the entity model without sending a request to create. This is useful for comparing states.
        """
        try:

            name = name.strip('"')
            # validate client protocols
            valid_client_protocols = list()
            for proto in client_protocols:
                if not proto.lower() in VALID_SERVICE_PROTOCOLS:
                    raise Exception("ERROR: transparent protocol \"{}\" is not valid.".format(proto.lower()))
                else:
                    valid_client_protocols.append(proto.lower())

            valid_ports = self.validate_port_ranges(client_ports)
            intercept_config_data = {
                "addresses": client_hosts,
                "portRanges": valid_ports,
                "protocols": valid_client_protocols,
                "sourceIp": "$src_ip:$src_port"
            }

            host_config_data = {
                "forwardProtocol": True,
                "forwardAddress": True,
                "forwardPort": True,
                "allowedAddresses": client_hosts,
                "allowedPortRanges": valid_ports,
                "allowedProtocols": valid_client_protocols,
                "allowedSourceAddresses": transparent_hosts
            }

            service = self.create_service_with_configs(
                name=name,
                intercept_config_data=intercept_config_data,
                host_config_data=host_config_data,
                attributes=attributes,
                encryption_required=encryption_required,
                dry_run=dry_run
            )
            service_policy = self.create_service_policy(
                name=name+"-BindServicePolicy",
                services=["@"+name],
                endpoints=endpoints,
                type="Bind",
                semantic="AnyOf",
                dry_run=dry_run
            )
            service_edge_router_policy = self.create_service_edge_router_policy(
                name=name+"-ServiceEdgeRouterPolicy",
                services=["@"+name],
                edge_routers=edge_routers,
                semantic="AnyOf",
                dry_run=dry_run
            )

        except Exception as e:
            raise

        transparent_service = {
            "service": service,
            "service_policy": service_policy,
            "service_edge_router_policy": service_edge_router_policy
        }

        return(transparent_service)

    def delete_service_transparent(self, name: str):
        """Delete a transparent service and its associated bind service policy and service edge router policy.

        :param str name: name of transparent service to delete
        """
        try:

            service_policy_name = name+"-BindServicePolicy"
            service_policies = self.get_resources(name=service_policy_name, type="service-policies")
            if len(service_policies) == 1:
                service_policy_result = self.delete_resource(type="service-policy", id=service_policies[0]['id'])
            elif len(service_policies) > 1:
                raise Exception("ERROR: found more than one service policy with name \"{}\"".format(service_policy_name))
            else:
                service_policy_result = "NOT FOUND"

            service_edge_router_policy_name = name+"-ServiceEdgeRouterPolicy"
            service_edge_router_policies = self.get_resources(name=service_edge_router_policy_name, type="service-edge-router-policies")
            if len(service_edge_router_policies) == 1:
                service_edge_router_policy_result = self.delete_resource(type="service-edge-router-policy", id=service_edge_router_policies[0]['id'])
            elif len(service_edge_router_policies) > 1:
                raise Exception("ERROR: found more than one service with name \"{}\"".format(service_edge_router_policy_name))
            else:
                service_edge_router_policy_result = "NOT FOUND"

            services = self.get_resources(name=name, type="services")
            if len(services) == 1:
                service_result = self.delete_resource(type="service", id=services[0]['id'])
            elif len(services) > 1:
                raise Exception("ERROR: found more than one service with name \"{}\"".format(name))
            else:
                service_result = "NOT FOUND"

        except Exception as e:
            raise

        transparent_service = {
            "service": service_result,
            "service_policy": service_policy_result,
            "service_edge_router_policy": service_edge_router_policy_result
        }

        return(transparent_service)

    @docstring_parameters(valid_service_protocols=VALID_SERVICE_PROTOCOLS)
    def create_service_advanced(self, name: str, endpoints: list, client_hosts: list, client_ports: list, client_protocols: list = ["tcp"],
        server_hosts: list = [], server_ports: list = [], server_protocols: list = [], attributes: list = [],
        edge_router_attributes: list = ["#all"], encryption_required: bool = True, dry_run: bool = False,
        wait: int = 60, sleep: int = 10, progress: bool = False):
        """Create an "advanced" PSM-based (platform service model) endpoint-hosted service.

        Multiple client intercepts may be specified i.e. lists of domain names or IP addresses, ports, and protocols. If alternative
        server details are not given they are assumed to be the same as the intercept. If server details are provided then all intercepts
        flow to that server. You may constrain the list of allowed server hosts, ports, and protocols
        that may be forwarded.

        :param: name is required string
        :param: client_hosts is required list of strings that are intercept domain name or IPv4.
        :param: client_ports is required list of strings of the port ranges to intercept as ["80","5900:5999"].
        :param: client_protocols is optional list of strings of the transports to intercept. Choices: {valid_service_protocols}. Default is ["tcp"].
        :param: server_hosts is optional list of strings that are a domain name, IPv4, or IPv6. If omitted the client host is used.
        :param: server_ports is optional list of strings of the port ranges to forward as ["80","5900:5999"]. If omitted same client port is used.
        :param: server_protocols is optional list of strings of the server protocols to forward. Choices: {valid_service_protocols}. If omitted the client protocol is used.
        :param: attributes is optional list of strings of service roles to assign, associating the service with a matching AppWAN. Default is [].
        :param: edge_router_attributes is optional list of strings of router roles or router names that can "see" this service. Default is ["#all"].
        :param: endpoints is optional list of strings of endpoints' #hashtag or @name that will host this service.
        :param: encryption_required is optional Boolean. Default is to enable edge-to-edge encryption.
        :param: dry_run is optional Boolean where True returns only the entity model without sending a request.
        """
        name = name.strip('"')
        try:
            # validate roles
            for role in attributes:
                if not role[0:1] == '#':
                    raise Exception('ERROR: invalid role "{:s}". Must begin with "#"'.format(role))

            # these elements could be a single port as integer or a string with one or two ports separated by a : or -
            valid_client_ports = self.validate_port_ranges(client_ports)
            valid_server_ports = self.validate_port_ranges(server_ports)

            # validate client protocols
            valid_client_protocols = list()
            for proto in client_protocols:
                if not proto.lower() in VALID_SERVICE_PROTOCOLS:
                    raise Exception("ERROR: client intercept protocol \"{}\" is not valid.".format(proto.lower()))
                else:
                    valid_client_protocols.append(proto.lower())

            # validate server protocols
            valid_server_protocols = list()
            for proto in server_protocols:
                if not proto.lower() in VALID_SERVICE_PROTOCOLS:
                    raise Exception("ERROR: server protocol \"{}\" is not valid.".format(proto.lower()))
                else:
                    valid_server_protocols.append(proto.lower())

            # resolve exit hosting params
            server_egress = dict()
            if server_hosts and len(server_hosts) == 1:
                server_egress["host"] = server_hosts[0]
            elif server_hosts and len(server_hosts) > 1:
                server_egress["forwardHost"] = True
                server_egress["allowedHosts"] = server_hosts
            else:
                server_egress["forwardHost"] = True
                server_egress["allowedHosts"] = client_hosts

            if valid_server_ports and len(valid_server_ports) == 1 and valid_server_ports[0]['low'] == valid_server_ports[0]['high']:
                server_egress["port"] = valid_server_ports[0]['low']
            elif valid_server_ports:
                server_egress["forwardPort"] = True
                server_egress["allowedPortRanges"] = valid_server_ports
            else:
                server_egress["forwardPort"] = True
                server_egress["allowedPortRanges"] = valid_client_ports

            if valid_server_protocols and len(valid_server_protocols) == 1:
                server_egress["protocol"] = valid_server_protocols[0]
            elif valid_server_protocols and len(valid_server_protocols) > 1:
                server_egress["forwardProtocol"] = True
                server_egress["allowedProtocols"] = valid_server_protocols
            else:
                server_egress["forwardProtocol"] = True
                server_egress["allowedProtocols"] = valid_client_protocols


            # parse out the elements in the list of endpoints as one of #attribute, UUID, or resolvable Endoint name
            bind_endpoints = list()
            for endpoint in endpoints:
                if endpoint[0:1] == '#':
                    bind_endpoints.append(endpoint) # is an endpoint role attribute
                else:
                    # strip leading @ if present and re-add later after verifying the named endpoint exists
                    if endpoint[0:1] == '@':
                        endpoint = endpoint[1:]

                    # if UUIDv4 then resolve to name, else verify the named endpoint exists
                    if is_uuidv4(endpoint): # assigned below under "else" if already a UUID
                        try:
                            name_lookup = self.get_resource(type="endpoint",id=endpoint)
                            endpoint_name = name_lookup['name']
                        except Exception as e:
                            raise Exception('ERROR: Failed to find exactly one hosting endpoint with ID "{}". Caught exception: {}'.format(endpoint, e))
                        else: bind_endpoints.append('@'+endpoint_name) # is an existing endpoint's name resolved from UUID
                    else:
                        try:
                            name_lookup = self.get_resources(type="endpoints",name=endpoint)[0]
                            endpoint_name = name_lookup['name']
                        except Exception as e:
                            raise Exception('ERROR: Failed to find exactly one hosting endpoint named "{}". Caught exception: {}'.format(endpoint, e))
                        # append to list after successfully resolving name to ID
                        else: bind_endpoints.append('@'+endpoint_name) # is an existing endpoint's name

            headers = {
                "authorization": "Bearer " + self.token
            }
            body = {
                "networkId": self.id,
                "name": name,
                "encryptionRequired": encryption_required,
                "modelType": "AdvancedTunnelerToEndpoint",
                "model": {
                    "bindEndpointAttributes": bind_endpoints,
                    "clientIngress" : {
                        "addresses": client_hosts,
                        "ports": valid_client_ports,
                        "protocols": valid_client_protocols
                    },
                    "serverEgress": server_egress,
                    "edgeRouterAttributes" : edge_router_attributes
                },
                "attributes" : attributes,
            }

            params = dict()
            # params = {
            #     "beta": ''
            # }

            if dry_run:
                return(body)

            response = http.post(
                self.audience+'core/v2/services',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body,
                params=params
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/services'}, got {e}")

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, NETWORK_RESOURCES['services'].create_responses):
            try:
                started = response.json()
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        # extract UUIDv4 part 6 in https://gateway.production.netfoundry.io/core/v2/process/5dcef954-9d02-4751-885e-63184c5dc8f2
        process_id = started['_links']['process']['href'].split('/')[6]

        # a non-zero integer value for 'wait' guarantees that the method returns the fully-provisioned entity's object or times out
        #  with an exception, and a zero value guarantees only that the async create process started successfully within a short time
        # frame
        if wait:
            try:
                self.wait_for_status(expect="FINISHED",type="process", id=process_id, wait=wait, sleep=sleep, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'FINISHED'")
            try:
                # this may be redundant, but in any case was already present as a mechanism for fetching the finished entity,
                #  and may still serve as insurance that the zitiId is in fact defined when process status is FINISHED
                finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="service",
                                                            id=started['id'], wait=3, sleep=1)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for property 'zitiId' to be defined")
            return(finished)
        else:
            try:
                self.wait_for_statuses(expected_statuses=["STARTED","FINISHED"],type="process", id=process_id, wait=5, sleep=2, progress=progress)
            except Exception as e:
                raise Exception("ERROR: timed out waiting for process status 'STARTED' or 'FINISHED'")
            return(started)

    # the above method was renamed to follow the development of PSM-based services (platform service models)
    create_endpoint_service = create_service_advanced

    def create_app_wan(self, name: str, endpoint_attributes: list = [], service_attributes: list = [], posture_check_attributes: list = [],
                        wait: int = 10):
        """Create an AppWAN.

        :param name:                        a meaningful, unique name
        :param endpoint_attributes:         a list of endpoint hashtag role attributes and endpoint names
        :param service_attributes:          a list of service hashtag role attributes and service names
        :param posture_check_attributes:    a list of posture hashtag role attributes and posture names
        """
        try:
            headers = {
                "authorization": "Bearer " + self.token
            }
            for role in endpoint_attributes+service_attributes+posture_check_attributes:
                if not re.match('^[#@]', role):
                    raise Exception("ERROR: role attributes on an AppWAN must begin with # or @")
            body = {
                "networkId": self.id,
                "name": name.strip('"'),
                "endpointAttributes": endpoint_attributes,
                "serviceAttributes": service_attributes,
                "postureCheckAttributes": posture_check_attributes
            }

            response = http.post(
                self.audience+'core/v2/app-wans',
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                json=body
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/app-wans'}, got {e}")

        any_in = lambda a, b: any(i in b for i in a)
        response_code_symbols = [s.upper() for s in STATUS_CODES._codes[response_code]]
        if any_in(response_code_symbols, NETWORK_RESOURCES['app-wans'].create_responses):
            try:
                started = response.json()
            except ValueError as e:
                raise RuntimeError(f"failed to load JSON from POST response, got {e}")
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        # AppWANs are created in a blocking, synchronous manner, and so zitiId should be defined
        if wait and not started['zitiId']:
            finished = self.wait_for_property_defined(property_name="zitiId", property_type=str, entity_type="app-wan", id=started['id'], wait=wait)
            return(finished)
        else:
            return(started)

    def get_network_by_name(self, name: str):
        """Get one network from the current group by network name.

        :param: name required name of the NF network may contain quoted whitespace
        """
        params = {
            "findByNetworkGroupId": self.network_group_id,
            "findByName": name,
        }
        try:
            networks = self.get_resources(type='networks',**params)
        except Exception as e:
            raise RuntimeError(f"failed to get networks: {e}")
        else:
            if len(networks) == 1:
                return(networks[0])
            else:
                raise RuntimeError(f"failed to find exactly one network named '{name}', found {len(networks)}: '{','.join([n['name'] for n in networks])}'")

    def get_network_by_id(self,network_id):
        """Return the network object for a particular UUID.

        :param str network_id: the UUID of the network
        """
        url = self.audience+'core/v2/networks/'+network_id
        headers = { "authorization": "Bearer " + self.token }
        try:
            network, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get network from url: '{url}'")
        else:
            return(network)

    def get_controller_secrets(self, id: str):
        """Return the controller management login credentials as {zitiUserId: ASDF, zitiPassword: ASDF}.

        Note that this function requires privileged access to the controller and is intended for emergency, read-only operations by customer support engineers.
        :param id: the UUID of the network controller
        """
        url = self.audience+'core/v2/network-controllers/'+id+'/secrets'
        headers = { "authorization": "Bearer " + self.token }
        try:
            secrets, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get secrets from url: '{url}'")
        else:
            try:
                ziti_secrets_keys = ['zitiUserId','zitiPassword']
                assert(set(ziti_secrets_keys) & set(secrets.keys()) == set(ziti_secrets_keys))
            except AssertionError as e:
                logging.error(f"unexpected secrets keys in '{secrets.keys}', got HTTP response code '{status_symbol}'")
                raise e
            return(secrets)

    def get_controller_session(self, id: str):
        """Return the controller management API login session token as {sessionToken: UUID, expiresAt: DATETIME}.

        Note that this function requires privileged access to the controller and is intended for emergency, read-only operations by customer support engineers.
        :param id: the UUID of the network controller
        """
        url = self.audience+'core/v2/network-controllers/'+id+'/session'
        headers = { "authorization": "Bearer " + self.token }
        try:
            session, status_symbol = get_generic_resource(url=url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get session from url: '{url}'")
        else:
            try:
                ziti_session_keys = ['expiresAt','sessionToken']
                assert(set(ziti_session_keys) & set(session.keys()) == set(ziti_session_keys))
            except AssertionError as e:
                logging.error(f"unexpected secrets keys in '{session.keys}', got HTTP response code '{status_symbol}'")
                raise e
            return(session)

    def wait_for_property_defined(self, property_name: str, property_type: object = str, entity_type: str = "network", wait: int = 60, sleep: int = 3, id: str = None, progress: bool = False):
        """Poll until expiry for the expected property to become defined with the any value of the expected type.

        :param: property_name a top-level property to wait for e.g. `zitiId`
        :param: property_type optional Python instance type to expect for the value of property_name
        :param: id the UUID of the entity having a status if entity is not a network
        :param: entity_type optional type of entity e.g. network (default), endpoint, service, edge-router
        :param: wait optional SECONDS after which to raise an exception defaults to five minutes (300)
        :param: sleep SECONDS polling interval
        """
        # use the id of this instance's network unless another one is specified
        if entity_type == "network" and not id:
            id = self.id

        now = time.time()

        if not wait >= sleep:
            raise RuntimeError(f"wait duration ({wait}) must be greater than or equal to polling interval ({sleep})")

        # poll for status until expiry
        if progress:
            sys.stdout.write(f"\twaiting for property {property_name} ({str(property_type)}) or until {time.ctime(now+wait)}.")

#        response_code = int()
        property_value = None
        while time.time() < now+wait:
            if progress:
                sys.stdout.write('.') # print a stop each iteration to imply progress
                sys.stdout.flush()

            try:
                entity = self.get_resource(type=entity_type, id=id)
            except Exception as e:
                raise

            # if expected property value is not null then evaluate type, else sleep
            if entity.get(property_name) and entity[property_name]:
                property_value = entity[property_name]
                # if expected type then return, else sleep
                if isinstance(property_value, property_type):
                    if progress:
                        print() # newline terminates progress meter
                    return(entity)
                else:
                    if progress:
                        sys.stdout.write(f"\n{entity['name']:^19s}:{property_name:^19s} ({str(property_type)}):")
                    time.sleep(sleep)
            else:
                if progress:
                    sys.stdout.write(f"\n{'fetching':^19s}:{property_name:^19s} ({str(property_type)}):")
                time.sleep(sleep)

        #
        if progress:
            print() # newline terminates progress meter

        if not property_value:
            raise RuntimeError(f"failed to find any value for property '{property_name}'")
        else:
            raise RuntimeError(f"timed out waiting for property {property_name} to have expected type: {str(property_type)}")

    @docstring_parameters(resource_entity_types = str(NETWORK_RESOURCES.keys()))
    def wait_for_entity_name_exists(self, entity_name: str, entity_type: str, wait: int = 60, sleep: int = 3, progress: bool = False):
        """Continuously poll until expiry for the expected entity name to exist.

        :param: entity_name
        :param: entity_type is singular or plural form, choices: {resource_entity_types}
        :param: wait optional SECONDS after which to raise an exception defaults to five minutes (300)
        :param: sleep SECONDS polling interval
        :param: progress print a horizontal progress meter as dots, default false
        """
        now = time.time()

        if not wait >= sleep:
            raise RuntimeError(f"wait duration ({wait}) must be greater than or equal to polling interval ({sleep})")

        if not NETWORK_RESOURCES.get(plural(entity_type)):
            raise Exception(f"ERROR: unknown type '{entity_type}'. Choices: {','.join(NETWORK_RESOURCES.keys())}")

        # poll for status until expiry
        if progress:
            sys.stdout.write(f"\twaiting for entity {entity_name} ({str(entity_type)}) or until {time.ctime(now+wait)}.")

        found_entities = []
        while time.time() < now+wait:
            if progress:
                sys.stdout.write('.') # print a stop each iteration to imply progress
                sys.stdout.flush()

            try:
                found_entities = self.get_resources(type=plural(entity_type), name=entity_name)
            except Exception as e:
                raise

            # if expected entity exists then verify name, else sleep
            if len(found_entities) > 1:
                if progress:
                    print() # newline terminates progress meter
                raise RuntimeError(f"found more than one {singular(entity_type)} named '{entity_name}'.")
            elif len(found_entities) == 1:
                if progress:
                    print() # newline terminates progress meter
                return(found_entities[0])
            else:
                if progress:
                    sys.stdout.write(f"\n{'fetching':^19s}:{entity_name:^19s} ({str(entity_type)}):")
                time.sleep(sleep)

        if progress:
            print() # newline terminates progress meter

        raise RuntimeError(f"failed to find one {singular(entity_type)} named '{entity_name}'")

    def wait_for_status(self, expect: str = "PROVISIONED", type: str = "network", wait: int = 300, sleep: int = 20, id: str = None, progress: bool = False):
        """Continuously poll for the expected status until return Boolean true or raise exception.

        :param expect: the expected status symbol e.g. PROVISIONED
        :param id: the UUID of the entity having a status if entity is not a network
        :param type: optional type of entity e.g. network (default), endpoint, service, edge-router
        :param wait: optional SECONDS after which to raise an exception defaults to five minutes (300)
        :param sleep: SECONDS polling interval
        """
        # use the id of this instance's network unless another one is specified
        if type == "network" and not id:
            id = self.id

        now = time.time()

        if not wait >= sleep:
            raise RuntimeError(f"wait duration ({wait}) must be greater than or equal to polling interval ({sleep})")

        # poll for status until expiry
        if progress:
            sys.stdout.write(f"\twaiting for status {expect} or until {time.ctime(now+wait)}.")

        status = str()
        response_code = int()
        while time.time() < now+wait and not status == expect:
            if progress:
                sys.stdout.write('.') # print a stop each iteration to imply progress
                sys.stdout.flush()

            try:
                entity_status = self.get_resource_status(type=type, id=id)
            except Exception as e:
                raise RuntimeError(f"unknown error getting status for type={type}, id={id}")

            if entity_status['status']: # attribute is not None if HTTP OK
                if not status or ( # print the starting status
                    status and not entity_status['status'] == status # print on subsequent changes
                ):
                    if progress:
                        sys.stdout.write(f"\n{entity_status['name']:^19s}:{entity_status['status']:^19s}:")
                status = entity_status['status']
            else:
                response_code = entity_status['response_code']

            if not expect == status:
                time.sleep(sleep)
        if progress:
            print() # newline terminates progress meter

        if status == expect:
            return(True)
        elif not status:
            raise RuntimeError(f"failed to read status while waiting for {expect}; got {entity_status['http_status']} ({entity_status['response_code']}")
        else:
            raise RuntimeError(f"timed out with status {status} while waiting for {expect}")

    def wait_for_statuses(self, expected_statuses: list, type: str = "network", wait: int = 300, sleep: int = 20, id: str = None, progress: bool = False):
        """Continuously poll for the expected statuses until expiry.

        :param expected_statuses: list of strings as expected status symbol(s) e.g. ["PROVISIONING","PROVISIONED"]
        :param id: the UUID of the entity having a status if entity is not a network
        :param type: optional type of entity e.g. network (default), endpoint, service, edge-router
        :param wait: optional SECONDS after which to raise an exception defaults to five minutes (300)
        :param sleep: SECONDS polling interval
        """
        # use the id of this instance's network unless another one is specified
        if type == "network" and not id:
            id = self.id

        now = time.time()

        if not wait >= sleep:
            raise RuntimeError(f"wait duration ({wait}) must be greater than or equal to polling interval ({sleep})")

        # poll for status until expiry
        if progress:
            sys.stdout.write(f"\twaiting for any status in {expected_statuses} or until {time.ctime(now+wait)}.")

        status = str()
        response_code = int()
        while time.time() < now+wait and not status in expected_statuses:
            if progress:
                sys.stdout.write('.') # print a stop each iteration to imply progress
                sys.stdout.flush()

            try:
                entity_status = self.get_resource_status(type=type, id=id)
            except Exception as e:
                raise

            if entity_status['status']: # attribute is not None if HTTP OK
                if not status or ( # print the starting status
                    status and not entity_status['status'] == status # print on subsequent changes
                ):
                    if progress:
                        sys.stdout.write(f"\n{entity_status['name']:^19s}:{entity_status['status']:^19s}:")
                status = entity_status['status']
            else:
                response_code = entity_status['response_code']

            if not status in expected_statuses:
                time.sleep(sleep)
        if progress:
            print() # newline terminates progress meter

        if status in expected_statuses:
            return(True)
        elif not status:
            raise RuntimeError(f"failed to read status while waiting for any status in {expected_statuses}; got {entity_status['http_status']} ({entity_status['response_code']})")
        else:
            raise RuntimeError(f"timed out with status {status} while waiting for any status in {expected_statuses}")

    def get_resource_status(self, type: str, id: str = None):
        """Get an entity's API status or the symbolic HTTP code.

        :param type: the type of entity e.g. network, endpoint, service, edge-router, edge-router-policy, posture-check
        :param id: the UUID of the entity having a status if not a network
        """
        params = dict()
        if not type == "network":
            params["networkId"] = self.id

        entity_url = self.audience+'core/v2/'
        if type == 'network':
            entity_url += 'networks/'+self.id
        elif type == 'process':
            entity_url += 'process/'+id
        elif id is None:
            logging.error("entity UUID must be specified if not a network")
            raise RuntimeError
        else:
            entity_url += plural(type)+'/'+id

        headers = { "authorization": "Bearer " + self.token }
        try:
            resource, status_symbol = get_generic_resource(url=entity_url, headers=headers, proxies=self.proxies, verify=self.verify)
        except Exception as e:
            raise RuntimeError(f"failed to get resource from url: '{entity_url}', got {e}")

        else:
            if resource.get('status'):
                status = resource['status']
            else:
                status = status_symbol

            if resource.get('name'):
                name = resource['name']
            elif resource.get('processorName'):
                name = resource['processorName']
            logging.debug(f"found {name or entity_url} with status {status}")
            return {
                "status": status,
                "name": name or None,
            }

    def rotate_edge_router_registration(self, id: str):
        """Rotate and return the registration key like {"registrationKey": str, "expiresAt": date}.

        :param id: the UUID of the edge router
        """
        try:
            headers = { "authorization": "Bearer " + self.token }
            entity_url = self.audience+'core/v2/edge-routers/'+id+'/registration-key'
            response = http.post(
                entity_url,
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with POST to {self.audience+'core/v2/edge-routers/'+id+'/registration-key'}, got {e}")

        if response_code == STATUS_CODES.codes.OK:
            try:
                registration_object = response.json()
            except Exception as e:
                raise RuntimeError(f"failed while parsing response as object, got:\n{response.text}")
            else:
                return(registration_object)
        else:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

    get_edge_router_registration = rotate_edge_router_registration

    def delete_resource(self, type: str, id: str = None, wait: int = 0, progress: bool = False):
        """Delete a resource.

        :param type: required entity type to delete i.e. network, endpoint, service, edge-router
        :param id: required entity UUID to delete
        :param wait: optional seconds to wait for entity destruction
        """
        try:
            headers = { "authorization": "Bearer " + self.token }
            entity_url = self.audience+'core/v2/networks/'+self.id
            expected_responses = [
                STATUS_CODES.codes.ACCEPTED,
                STATUS_CODES.codes.OK
            ]
            if not type == 'network':
                if id is None:
                    raise Exception("ERROR: need entity UUID to delete")
                entity_url = self.audience+'core/v2/'+plural(type)+'/'+id
            logging.debug(f"deleting {entity_url}")
            params = dict()
            # if type == "service":
            #     params["beta"] = ''

            response = http.delete(
                entity_url,
                proxies=self.proxies,
                verify=self.verify,
                headers=headers,
                params=params
            )
            response_code = response.status_code
        except Exception as e:
            raise RuntimeError(f"error with DELETE to {entity_url}, got {e}")

        if not response_code in expected_responses:
            raise RuntimeError(f"got unexpected HTTP code {STATUS_CODES._codes[response_code][0].upper()} ({response_code}) and response {response.text}")

        if not wait == 0:
            try:
                self.wait_for_property_defined(
                    property_name="deletedAt",
                    property_type=str,
                    entity_type=type,
                    id=self.id if type == 'network' else id,
                    wait=wait,
                    sleep=1,
                    progress=progress
                )
            except Exception as e:
                raise

        return(True)
