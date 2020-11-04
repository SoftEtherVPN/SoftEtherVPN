#!/bin/bash

set -eux

BUILD_BINARIESDIRECTORY="${BUILD_BINARIESDIRECTORY:-build}"

cd $BUILD_BINARIESDIRECTORY

./vpnserver start

#
# wait until server listen 443
#
set +e
started="false"
for i in 1 2 3 4 5 6
do
    s=$(echo exit | telnet 127.0.0.1 443 | grep "Connected")
    if [ "$s" != "" ]
    then
       started="true"
       break
    fi
    sleep 10  
done

set -e

if [ "$started" == "false" ]
then
   echo "vpnserver is not listening 127.0.0.1:443"
   exit 1
fi

./vpncmd 127.0.0.1:443 /SERVER /HUB:DEFAULT /CMD:SecureNatEnable
./vpncmd 127.0.0.1:443 /SERVER /CMD:"ProtoOptionsSet OpenVPN /NAME:Enabled /VALUE:True"
./vpncmd 127.0.0.1:443 /SERVER /CMD:"PortsUDPSet 1194"
./vpncmd 127.0.0.1:443 /SERVER /HUB:DEFAULT /CMD:"UserCreate test /GROUP:none /REALNAME:none /NOTE:none"
./vpncmd 127.0.0.1:443 /SERVER /HUB:DEFAULT /CMD:"UserPasswordSet test /PASSWORD:test"
./vpncmd 127.0.0.1:443 /SERVER /CMD:"OpenVpnMakeConfig my_openvpn_config.zip"

unzip -d /tmp my_openvpn_config.zip
