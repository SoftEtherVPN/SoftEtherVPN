#!/bin/sh

set -eux

build/vpnserver start

build/vpncmd 127.0.0.1:443 /SERVER /HUB:DEFAULT /CMD:SecureNatEnable
build/vpncmd 127.0.0.1:443 /SERVER /CMD:"OpenVpnEnable yes /PORTS:1194"
build/vpncmd 127.0.0.1:443 /SERVER /HUB:DEFAULT /CMD:"UserCreate test /GROUP:none /REALNAME:none /NOTE:none"
build/vpncmd 127.0.0.1:443 /SERVER /HUB:DEFAULT /CMD:"UserPasswordSet test /PASSWORD:test"
build/vpncmd 127.0.0.1:443 /SERVER /CMD:"OpenVpnMakeConfig ~/my_openvpn_config.zip"

unzip -d /tmp ~/my_openvpn_config.zip
