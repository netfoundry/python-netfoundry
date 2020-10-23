import netfoundry; 
nfapi = netfoundry.client(
    credentials="/home/kbingham/.netfoundry/credentials.json", 
    environment="staging"#, proxy="http://localhost:4321"
);
print(nfapi.networksByName);