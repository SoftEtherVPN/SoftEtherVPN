#!/bin/bash

set -eux

BUILD_BINARIESDIRECTORY="${BUILD_BINARIESDIRECTORY:-build}"

sudo dpkg -i $BUILD_BINARIESDIRECTORY/softether-common*.deb
sudo dpkg -i $BUILD_BINARIESDIRECTORY/softether-vpnbridge*.deb
sudo dpkg -i $BUILD_BINARIESDIRECTORY/softether-vpnclient*.deb
sudo dpkg -i $BUILD_BINARIESDIRECTORY/softether-vpncmd*.deb
sudo dpkg -i $BUILD_BINARIESDIRECTORY/softether-vpnserver*.deb

sudo systemctl restart softether-vpnserver || (sudo journalctl -xe --no-pager >> systemctl.log && appveyor PushArtifact systemctl.log && exit 1)

