# SoftetherVPN Container images

This container is designed to be as small as possible and host a SoftEther VPN Server, Bridge or Client.
It´s based on Alpine so resulting Image is kept as small as 15MB!

## Not working 

* bridging to a physical Ethernet adapter 

## working

* OpenVPN
* L2tp
* SSL 
* SecureNAT
* Wireguard (not with the "stable" tag)



## Available Tags


|Image|Description|
|---|---|
|softethervpn/vpnserver:stable|Latest stable release from https://github.com/SoftEtherVPN/SoftEtherVPN_Stable|
|softethervpn/vpnserver:v4.39-9772-beta|Tagged build|
|softethervpn/vpnserver:latest|Latest commits from https://github.com/SoftEtherVPN/SoftEtherVPN|


You should always specify your wanted version like `softethervpn/vpnserver:5.02.5180`

## Usage docker run

This will keep your config and Logfiles in the docker volume `softetherdata`

`docker run -d --rm --name softether-vpn-server -v softetherdata:/var/lib/softether -v softetherlogs:/var/log/softether -p 443:443/tcp -p 992:992/tcp -p 1194:1194/udp -p 5555:5555/tcp -p 500:500/udp -p 4500:4500/udp -p 1701:1701/udp --cap-add NET_ADMIN softethervpn/vpnserver:stable`

## Port requirements

As there are different operating modes for SoftetherVPN there is a variety of ports that might or might not be needed.
For operation with Softether Clients at least 443, 992 or 5555 is needed.
See https://www.softether.org/4-docs/1-manual/1/1.6 for reference on the Softether ports.
Others are commented out in the docker-compose example.

## Usage docker-compose

The same command can be achieved by docker-compose, the docker compose file is in the repository.
You can specify the respective docker-compose.yaml like so: 

`docker-compose -f docker-compose.vpnclient.yaml up -d`

By default the docker-compose.yaml is used: 

```
version: '3'

services:
  softether:
    image: softethervpn/vpnserver:latest
    cap_add:
      - NET_ADMIN
    restart: always
    ports:
      #- 53:53         #DNS tunneling
      - 443:443         #Management and HTTPS tunneling
      #- 992:992         #HTTPS tunneling
      #- 1194:1194/udp #OpenVPN 
      #- 5555:5555       #HTTPS tunneling
      #- 500:500/udp   #IPsec/L2TP
      #- 4500:4500/udp #IPsec/L2TP
      #- 1701:1701/udp #IPsec/L2TP
    volumes:
      - "/etc/localtime:/etc/localtime:ro"
      - "/etc/timezone:/etc/timezone:ro"
      - "./softether_data:/var/lib/softether"
      - "./softether_log:/var/log/softether"
      # - "./adminip.txt:/var/lib/softether/adminip.txt:ro"
```

### Use vpncmd

With newer releases vpncmd is directly in the container so you can use it to configure vpn. You can can run it once the container is running :

`docker exec -it softether-vpn-server vpncmd localhost`
example to configure a vpnclient

```
docker exec -it softether-vpn-server vpncmd localhost /client

VPN Client> AccountSet homevpn /SERVER:192.168.1.1:443 /HUB:VPN
VPN Client> AccountPasswordSet homevpn /PASSWORD:verysecurepassword /TYPE:standard
VPN Client> AccountConnect homevpn

#Automatically connect once container starts
VPN Client> AccountStartupSet homevpn

#Checking State
VPN Client> AccountStatusGet homevpn

```

## Building 

` docker build --target vpnclient -t softethevpn:latest .`