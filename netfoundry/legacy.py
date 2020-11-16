def waitForHttpResponse(self, status, type, netId, wait, id=0):
    """continuously poll for the expected HTTP response code until expiry
    :param type: the type of entity e.g. network, endpoint, service
    :param id: the UUID of the entity having a status
    :param status: string that is the symbolic name of the expected status code
    :param wait: SECONDS after which to raise an exception
    Example: status NOT_FOUND will succeed when response is HTTP 404
    """

    now = time.time()

    # poll for status until expiry
    sys.stdout.write(
        '\twaiting for status {:s} ({:d}) or until {:s}.'.format(
            status,
            requests.status_codes.codes[status],
            time.ctime(now+wait)
        )
    )
    # resolve the expected status to an HTTP code
    status_code = requests.status_codes.codes[status]
    # initialize a variable to store the last checked HTTP code
    http_code = int()
    while time.time() < now+wait and not status_code == http_code:
        sys.stdout.write('.')
        sys.stdout.flush()
        try:
            entity = self.getResourceStatus(type=type,
                                    netId=netId,
                                    id=id)
            if not http_code or (
                http_code and
                not http_code == entity['http_code']
            ):
                sys.stdout.write(
                    '\n\t\t:'
                    +'{:^19s}'.format(
                        requests.status_codes._codes[
                            entity['http_code']
                        ][0].upper()
                    )
                    +':'

                )

            http_code = entity['http_code']
        except:
            raise

        time.sleep(15)

    print() # newline terminates progress meter

    if status_code == http_code:
        return(True)
    else:
        raise Exception(
            'timed out with status {} ({}) while waiting for {} ({})'.format(
                requests.status_codes._codes[http_code][0].upper(),
                http_code,
                status,
                status_code,
            )
        )

def patchAttributes(token,type,resource):
    """return the new resource object
        :token [required] the API access token
        :type [required] one of endpoints, edge-routers, services
        :resource [required] the resource object to PUT 
    """
    try:
        headers = { 
            'Content-Type': 'application/json',
            "authorization": "Bearer " + token 
        }
        response = requests.patch(
            self.audience+'/core/v2/'+type+'/'+resource['id'],
            json={
                'name': resource['name'],
                'attributes': resource['attributes']
            },
            headers=headers
        )
        http_code = response.status_code
    except:
        raise

    if http_code == requests.status_codes.codes[RESOURCES[type]['expect']]: # HTTP 200
        try:
            updated = json.loads(response.text)
        except ValueError as e:
            eprint('ERROR: failed to load updated resource object from PUT response body')
            raise(e)
    else:
        raise Exception(
            'unexpected response: {} (HTTP {:d}\n{})'.format(
                requests.status_codes._codes[http_code][0].upper(),
                http_code,
                response.text
            )
        )

    return(updated)

def post(self,
    method,
    json,
    expected_response="ACCEPTED"):
    """
    post arbitrary data as JSON to an API method
    """

    headers = {
        'Content-Type': 'application/json',
        "authorization": "Bearer " + self.token
    }

    try:
        response = requests.post(
            self.audience+"core/v2"+method,
            json=json,
            headers=headers,
            proxies=self.proxies,
            verify=self.verify
        )
        http_code = response.status_code
    except:
        raise

    if not http_code == requests.status_codes.codes[expected_response]:
        raise Exception('unexpected response: {} (HTTP {:d})'.format(
            requests.status_codes._codes[http_code][0].upper(),
            http_code)
        )
    text = response.text
    return(text)


def createIpNetworkService(
        self,
        netId,
        name,
        gatewayIp,
        gatewayNetmask,
        interceptIp,
        endpointId,
        wait=0):
    """publish a subnetwork (IP or range described by network address and netmask)
    :param netId: network UUID
    :param name: descriptive name allowing whitespace
    :param gatewayIp: the network address of the subnet (lowest IP)
    :param gatewayNetmask: the netmask describing the size of the published subnet
    :param interceptIp: the network address of the subnet used by clients
    :param endpointId: UUID of the serving gateway that will provide this service
    :param wait: optional wait seconds for service to become ACTIVE
    """
    request = {
        "name": name,
        "serviceClass": "GW",
        "gatewayIp": gatewayIp,
        "gatewayNetmask": gatewayNetmask,
        "interceptIp": interceptIp,
        "endpointId": endpointId
    }

    headers = {
        'Content-Type': 'application/json',
        "authorization": "Bearer " + self.token
    }

    try:
        response = requests.post(
            self.audience+"core/v2/networks/"+netId+"/services",
            json=request,
            headers=headers,
            proxies=self.proxies,
            verify=self.verify)
        http_code = response.status_code
    except:
        raise

    if not http_code == requests.status_codes.codes.ACCEPTED:
        raise Exception(
            'unexpected response: {} (HTTP {:d})'.format(
                requests.status_codes._codes[http_code][0].upper(),
                http_code
            )
        )

    svcId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]

    # expected value is UUID of new endpoint
    UUID(svcId, version=4) # validate the returned value is a UUID

    if not wait == 0:
        try:
            self.waitForStatus(
                status='ACTIVE',
                type='service',
                netId=netId,
                id=svcId,
                wait=wait)
        except:
            raise

    return(svcId)

def createAwsGateway(self, name, netId, dataCenterId, wait=0, family="dvn", managed=False):
    """
    create an AWS gateway endpoint with
    :param name: gateway name
    :param netId: network UUID
    :param dataCenterId: datacenter UUID
    :param wait: optional wait seconds for endpoint to become REGISTERED (400)
    :param family: optional family indicating endpoint type if not "dvn"
    :param managed: optional boolean indicating instance is launched and managed by MOP
    """

    if not managed and family == "ziti":
        endpointType = "ZTNHGW"
    elif not managed and family == "dvn":
        endpointType = "AWSCPEGW"
    elif managed and family == "ziti":
        endpointType = "ZTGW"
    elif managed and family == "dvn":
        endpointType = "GW"
    else:
        raise Exception(
            'unexpected family "{}" or endpoint type "{}"'.format(
                family,
                endpointType
            )
        )

    request = {
        "name": name,
        "endpointType": endpointType,
        "dataCenterId": dataCenterId
    }

    headers = {
        'Content-Type': 'application/json',
        "authorization": "Bearer " + self.token
    }

    try:
        response = requests.post(self.audience+"core/v2/networks/"+netId+"/endpoints",
                                    json=request,
                                    headers=headers,
                                    proxies=self.proxies,
                                    verify=self.verify
                                )
        http_code = response.status_code
    except:
        raise

    if not http_code == requests.status_codes.codes.ACCEPTED:
        raise Exception(
            'unexpected response: {} (HTTP {:d})'.format(
                requests.status_codes._codes[http_code][0].upper(),
                http_code
            )
        )

    endId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]

    # expected value is UUID of new endpoint
    UUID(endId, version=4) # validate the returned value is a UUID

    if not wait == 0:
        try:
            self.waitForStatus(status='REGISTERED',
                                        type='endpoint',
                                        netId=netId,
                                        id=endId,
                                        wait=wait)
        except:
            raise

    return(endId)

def createVcpeGateway(self, name, netId, geoRegionId, wait=0):
    """
    create a self-hosted gateway endpoint with
    :param name: gateway name
    :param netId: network UUID
    :param geoRegionId: geo region UUID
    :param wait: optional wait seconds for endpoint to become REGISTERED (400)
    """
    request = {
        "name": name,
        "endpointType": "VCPEGW",
        "geoRegionId": geoRegionId
    }

    headers = {
        'Content-Type': 'application/json',
        "authorization": "Bearer " + self.token
    }

    try:
        response = requests.post(self.audience+"core/v2/networks/"+netId+"/endpoints",
                                    json=request,
                                    headers=headers,
                                    proxies=self.proxies,
                                    verify=self.verify
                                )
        http_code = response.status_code
    except:
        raise

    if not http_code == requests.status_codes.codes.ACCEPTED:
        raise Exception(
            'unexpected response: {} (HTTP {:d})'.format(
                requests.status_codes._codes[http_code][0].upper(),
                http_code
            )
        )

    endId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]

    # expected value is UUID of new endpoint
    UUID(endId, version=4) # validate the returned value is a UUID

    if not wait == 0:
        try:
            self.waitForStatus(status='REGISTERED',
                                        type='endpoint',
                                        netId=netId,
                                        id=endId,
                                        wait=wait)
        except:
            raise

    return(endId)

def createIpHostService(self,
                        netId,
                        name,
                        networkIp,
                        networkFirstPort,
                        networkLastPort,
                        interceptIp,
                        interceptFirstPort,
                        interceptLastPort,
                        protocolType,
                        endpointId,
                        wait=0
                        ):
    """publish a host:port(s) couplet
    :param netId: network UUID
    :param name: descriptive name allowing whitespace
    :param networkIp: interface or masquerade address of the published service
    :param networkFirstPort: lower bound of published port range
    :param networkLastPort: upper bound of published port range
    :param interceptIp: destination address used by clients
    :param interceptFirstPort: lower bound of destination port range
    :param interceptLastPort: upper bound of destination port range
    :param protocolType: one of tcp, udp
    :param endpointId: UUID of the serving gateway that provides this service
    :param wait: optional wait seconds for service to become ACTIVE
    """
    request = {
        "name": name,
        "serviceClass": "CS",
        "networkIp": networkIp,
        "networkFirstPort": networkFirstPort,
        "networkLastPort": networkLastPort,
        "interceptIp": interceptIp,
        "interceptFirstPort": interceptFirstPort,
        "interceptLastPort": interceptLastPort,
        "protocolType": protocolType,
        "endpointId": endpointId,
        "serviceType": protocolType.upper(),
        "transparency": "NO",
        "bridgeStp": "YES",
        "collectionLocation": "BOTH",
        "cryptoLevel": "STRONG",
        "dnsOptions": "NONE",
        "icmpTunnel": "YES",
        "localNetworkGateway": "YES",
        "multicast": "OFF",
        "pbrType": "WAN",
        "permanentConnection": "NO",
        "rateSmoothing": "YES",
        "serviceInterceptType": "IP"
    }
    headers = {
        'Content-Type': 'application/json',
        "authorization": "Bearer " + self.token
    }

    try:
        response = requests.post(self.audience+"core/v2/networks/"+netId+"/services",
                                    json=request,
                                    headers=headers,
                                    proxies=self.proxies,
                                    verify=self.verify
                                )
        http_code = response.status_code
    except:
        raise

    if not http_code == requests.status_codes.codes.ACCEPTED:
        raise Exception(
            'unexpected response: {} (HTTP {:d})'.format(
                requests.status_codes._codes[http_code][0].upper(),
                http_code
            )
        )

    svcId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]

    # expected value is UUID of new endpoint
    UUID(svcId, version=4) # validate the returned value is a UUID

    if not wait == 0:
        try:
            self.waitForStatus(status='ACTIVE',
                                        type='service',
                                        netId=netId,
                                        id=svcId,
                                        wait=wait)
        except:
            raise

    return(svcId)

def createAppWan(self,
                    netId,
                    name,
                    wait=0
                ):
    """authorize endpoint(s) for service(s) where
    :param netId: network UUID
    :param name: descriptive name allowing whitespace
    """
    request = {
        "name": name,
    }

    headers = {
        'Content-Type': 'application/json',
        "authorization": "Bearer " + self.token
    }

    try:
        response = requests.post(self.audience+"core/v2/networks/"+netId+"/appWans",
                                    json=request,
                                    headers=headers,
                                    proxies=self.proxies,
                                    verify=self.verify
                                )
        #print(response)
        http_code = response.status_code
    except:
        raise

    if http_code == requests.status_codes.codes.ACCEPTED:
        appWanId = json.loads(response.text)['_links']['self']['href'].split('/')[-1]
    else:
        raise Exception(
            'unexpected response: {} (HTTP {:d})'.format(
                requests.status_codes._codes[http_code][0].upper(),
                http_code
            )
        )

    if not wait == 0:
        try:
            self.waitForStatus(status='ACTIVE',
                                        type='appWan',
                                        netId=netId,
                                        id=appWanId,
                                        wait=wait)
        except:
            raise

    return(appWanId)

def updateAppWan(self,
                    appWanId,
                    netId,
                    services,
                    endpoints=[],
                    endpointGroups=[],
                    wait=0
                ):
    """authorize endpoint(s) or endpoint group(s) or both for service(s) where
    :param appWanId: AppWAN UUID to update
    :param netId: network UUID housing the AppWAN
    :param services: list of service UUIDs to publish
    :param endpoints: optional list of endpoint UUIDs to authorize
    :param endpointGroups: optional list of endpoint group UUIDs to authorize
    """

    appWan = dict()

    appWan['services'] = {
        "ids": services
    }

    appWan['endpoints'] = {
        "ids": endpoints
    }

    appWan['endpointGroups'] = {
        "ids": endpointGroups
    }

    headers = {
        'Content-Type': 'application/json',
        "authorization": "Bearer " + self.token
    }

    for resource in ['services', 'endpoints', 'endpointGroups']:
        try:
            response = requests.post(
                self.audience+"core/v2/networks/"+netId+"/appWans/"+appWanId+"/"+resource,
                        json=appWan[resource],
                        headers=headers,
                        proxies=self.proxies,
                        verify=self.verify)
            #print(response)
            http_code = response.status_code
        except:
            raise

        if not http_code == requests.status_codes.codes.ACCEPTED:
            raise Exception(
                'unexpected response: {} (HTTP {:d})'.format(
                    requests.status_codes._codes[http_code][0].upper(),
                    http_code
                )
            )

        if not wait == 0:
            try:
                self.waitForStatus(status='ACTIVE',
                                            type='appWan',
                                            netId=netId,
                                            id=appWanId,
                                            wait=wait)
            except:
                raise

    return(True)

def describeResource(self, type, netId, id=0):
    """return the full object describing an entity
    :param type: the type of entity e.g. network, endpoint, service
    :param netId: the UUID of the network housing the entity
    :param id: the UUID of the entity having a status if not a network
    """

    try:
        headers = { "authorization": "Bearer " + self.token }
        entityUrl = self.audience+'core/v2/networks/'+netId
        if not type == 'network':
            if id == 0:
                raise Exception("ERROR: entity UUID must be specified if not a network")
            entityUrl += '/'+type+'s/'+id

        response = requests.get(entityUrl,
                                proxies=self.proxies,
                                verify=self.verify,
                                headers=headers)
        http_code = response.status_code
    except:
        raise

    if http_code == requests.status_codes.codes.OK:
        try:
            entity = json.loads(response.text)
        except:
            eprint('ERROR parsing entity object in response')
            raise
    else:
        status = None

    return(entity)