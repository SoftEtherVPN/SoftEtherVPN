#!/bin/bash

set -eux

BUILD_BINARIESDIRECTORY="${BUILD_BINARIESDIRECTORY:-build}"

cd $BUILD_BINARIESDIRECTORY

git clone https://github.com/openvpn/openvpn
cd openvpn
autoreconf -iv
./configure  > build.log 2>&1 || (cat build.log && exit 1)
make > build.log 2>&1 || (cat build.log && exit 1)

echo test > /tmp/auth.txt
echo test >> /tmp/auth.txt

CONFIG=`ls /tmp/*l3*ovpn`

cat << EOF > tests/t_client.rc
CA_CERT=fake
TEST_RUN_LIST="1 2"

OPENVPN_BASE="--remote 127.0.0.1 --config $CONFIG --auth-user-pass /tmp/auth.txt"

RUN_TITLE_1="testing udp/ipv4"
OPENVPN_CONF_1="--dev null --proto udp --port 1194 \$OPENVPN_BASE"

RUN_TITLE_2="testing tcp/ipv4"
OPENVPN_CONF_2="--dev null --proto tcp --port 1194 \$OPENVPN_BASE"
EOF

make test_scripts=t_client.sh check
