#!/bin/sh

set -eux

BUILD_BINARIESDIRECTORY="${BUILD_BINARIESDIRECTORY:-build}"

cd $BUILD_BINARIESDIRECTORY

./vpnserver start

./vpncmd 127.0.0.1:443 /SERVER /HUB:DEFAULT /CMD:SecureNatEnable
./vpncmd 127.0.0.1:443 /SERVER /CMD:"ProtoOptionsSet OpenVPN /NAME:Enabled /VALUE:True"
./vpncmd 127.0.0.1:443 /SERVER /CMD:"PortsUDPSet 1194"
./vpncmd 127.0.0.1:443 /SERVER /HUB:DEFAULT /CMD:"UserCreate test /GROUP:none /REALNAME:none /NOTE:none"
./vpncmd 127.0.0.1:443 /SERVER /HUB:DEFAULT /CMD:"UserPasswordSet test /PASSWORD:test"
./vpncmd 127.0.0.1:443 /SERVER /CMD:"OpenVpnMakeConfig my_openvpn_config.zip"

unzip -d /tmp my_openvpn_config.zip
