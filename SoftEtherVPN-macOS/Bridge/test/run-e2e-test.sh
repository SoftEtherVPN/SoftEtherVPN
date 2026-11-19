#!/bin/sh
# End-to-end test of the bridge (Linux or macOS), against a throwaway local
# VPN server.
#
#   run-e2e-test.sh <desktop build dir> <bridge build dir>
#
#   <desktop build dir>  a normal build of the repo root (./configure && make
#                        -C build): provides vpnserver, vpnclient, vpncmd,
#                        hamcore.se2
#   <bridge build dir>   a build of SoftEtherVPN-macOS/ (this folder's
#                        CMakeLists.txt): provides se_bridge_test
#
# The server gets one hub with SecureNAT (virtual DHCP + NAT), one user, a
# DHCP domain name and one pushed classless route, so the test covers
# everything the macOS split tunnel / split DNS settings are built from.
# A desktop vpnclient is used only to export a .vpn connection file, which the
# bridge then imports. No root and no network interface is needed.
set -eu

DESKTOP=$(cd "$1" && pwd)
BRIDGE=$(cd "$2" && pwd)
PORT=${SE_TEST_PORT:-5555}
WORK=$(mktemp -d)

cleanup()
{
	"$WORK/vpnserver" stop >/dev/null 2>&1 || true
	"$WORK/client/vpnclient" stop >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

cp "$DESKTOP/vpnserver" "$DESKTOP/vpncmd" "$DESKTOP/hamcore.se2" "$WORK/"
cp "$DESKTOP"/libcedar.* "$DESKTOP"/libmayaqua.* "$WORK/" 2>/dev/null || true
export LD_LIBRARY_PATH="$WORK:${LD_LIBRARY_PATH:-}"
export DYLD_LIBRARY_PATH="$WORK:${DYLD_LIBRARY_PATH:-}"

"$WORK/vpnserver" start >/dev/null

cmd()
{
	"$WORK/vpncmd" "localhost:$PORT" /SERVER "$@" >"$WORK/vpncmd.log" 2>&1 || {
		cat "$WORK/vpncmd.log"
		exit 1
	}
}

# Wait for the listener
i=0
until "$WORK/vpncmd" "localhost:$PORT" /SERVER /CMD About >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -lt 30 ] || { echo "vpnserver did not start"; exit 1; }
	sleep 1
done

cmd /CMD HubCreate TEST /PASSWORD:hubpw
cmd /HUB:TEST /PASSWORD:hubpw /CMD UserCreate u1 /GROUP:none /REALNAME:none /NOTE:none
cmd /HUB:TEST /PASSWORD:hubpw /CMD UserPasswordSet u1 /PASSWORD:pw1
cmd /HUB:TEST /PASSWORD:hubpw /CMD DhcpSet /START:192.168.30.10 /END:192.168.30.200 \
	/MASK:255.255.255.0 /EXPIRE:7200 /GW:192.168.30.1 /DNS:192.168.30.1 /DNS2:none \
	/DOMAIN:corp.example /LOG:yes /PUSHROUTE:10.20.0.0/255.255.0.0/192.168.30.1
cmd /HUB:TEST /PASSWORD:hubpw /CMD SecureNatEnable

# A .vpn file as the desktop client exports it (saved password included)
mkdir "$WORK/client"
cp "$DESKTOP/vpnclient" "$DESKTOP/hamcore.se2" "$WORK/client/"
"$WORK/client/vpnclient" start >/dev/null

ccmd()
{
	"$WORK/vpncmd" localhost /CLIENT /CMD "$@" >"$WORK/vpncmd.log" 2>&1 || {
		cat "$WORK/vpncmd.log"
		exit 1
	}
}

i=0
until "$WORK/vpncmd" localhost /CLIENT /CMD VersionGet >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -lt 30 ] || { echo "vpnclient did not start"; exit 1; }
	sleep 1
done

ccmd AccountCreate "Office VPN" "/SERVER:127.0.0.1:$PORT" /HUB:TEST /USERNAME:u1 /NICNAME:vpn0
ccmd AccountPasswordSet "Office VPN" /PASSWORD:pw1 /TYPE:standard
ccmd AccountExport "Office VPN" "/SAVEPATH:$WORK/office.vpn"
"$WORK/client/vpnclient" stop >/dev/null 2>&1 || true

export LD_LIBRARY_PATH="$BRIDGE/softether-core:$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="$BRIDGE/softether-core:$DYLD_LIBRARY_PATH"
export SE_TEST_VPN_FILE="$WORK/office.vpn"
SE_TEST_EXPECT_DOMAIN=corp.example SE_TEST_EXPECT_ROUTES=1 \
	"$BRIDGE/se_bridge_test" "$BRIDGE/softether-core/hamcore.se2" 127.0.0.1 "$PORT" TEST u1 pw1
