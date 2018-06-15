import netfoundry
import requests
import json

CLIENT_ID = "9jJ38zA6OZfN4A0nJPLfQnAeBvm2jqnM"
CLIENT_SECRET = "9uIjiifcyr8nZMq_63jaNlHqZp1N7kfpg_z3IZ61bIYyzBwtucrFOHDpK43F_j3d"
REGION = "us-east-1"

api = netfoundry.nfapi()

AUTH_ENDPOINT = api.authEndpoints["production"]
HEADERS = { 'content-type': "application/json" }
REQUEST = {
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "audience": "https://gateway.production.netfoundry.io/",
    "grant_type": "client_credentials"
}

RESPONSE = requests.post(AUTH_ENDPOINT,
                         json=REQUEST,
                         headers=HEADERS)
TOKEN = json.loads(RESPONSE.text)['access_token']

# construct the MOP client
api.client(auth=TOKEN)

DCID = api.dataCentersByRegion[REGION]

# create a network with controller in a particular datacenter region
NETID = api.createNetwork(name="helloNetwork",
                          region=REGION)

# create client and serving gateway endpoints
helloClientGwId = api.createGateway(name="helloClientGateway",
                                    netId=NETID,
                                    dataCenterId=DCID)

helloServingGwId = api.createGateway(name="helloServingGateway",
                                     netId=NETID,
                                     dataCenterId=DCID)
# create a client service
helloClientServiceId = api.createClientService(name="helloClientService",
                                               netId=NETID,
                                               networkIp="208.67.222.222",
                                               networkFirstPort=53,
                                               networkLastPort=53,
                                               interceptIp="5.3.5.3",
                                               interceptFirstPort=53,
                                               interceptLastPort=53,
                                               protocolType="udp")

# create an AppWAN
helloAppWanId = api.createAppWan(name="helloAppWan",
                                 netId=NETID)

# add the endpoints and service to the AppWAN
try:
    appWanResult = api.updateAppWan(netId=NETID,
                                    appWanId=helloAppWanId,
                                    services=[ helloClientServiceId ],
                                    endpoints=[ helloClientGwId, helloServingGwId ])
except:
    raise

# store existing network resources as a lookup object that resolves names to identifying UUIDs
helloNetworkNVirginia = api.walkNetwork(NETID)
