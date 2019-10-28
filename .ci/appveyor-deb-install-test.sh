#!/bin/bash

set -eux

sudo dpkg -i build/softether-common*.deb
sudo dpkg -i build/softether-vpnbridge*.deb
sudo dpkg -i build/softether-vpnclient*.deb
sudo dpkg -i build/softether-vpncmd*.deb
sudo dpkg -i build/softether-vpnserver*.deb

sudo systemctl restart softether-vpnserver || (sudo journalctl -xe --no-pager >> systemctl.log && appveyor PushArtifact systemctl.log && exit 1)

