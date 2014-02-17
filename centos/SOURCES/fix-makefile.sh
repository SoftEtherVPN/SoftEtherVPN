#!/bin/sh
# Works as of:
# %define majorversion 4.04
# %define minorversion 9412
# %define dateversion 2014.01.15
#
# sed commands could be optimized a bit, but I wanted to keep the makefiles exactly the same
# as the original to minimize issues. May modify this in the future.
#

# 32-bit
sed -i -e "s/^INSTALL_BINDIR=/INSTALL_BINDIR=\$\(DESTDIR\)/g" linux_32bit.mak
sed -i -e "s/^INSTALL_VPNSERVER_DIR=/INSTALL_VPNSERVER_DIR=\$\(DESTDIR\)/g" linux_32bit.mak
sed -i -e "s/^INSTALL_VPNBRIDGE_DIR=/INSTALL_VPNBRIDGE_DIR=\$\(DESTDIR\)/g" linux_32bit.mak
sed -i -e "s/^INSTALL_VPNCLIENT_DIR=/INSTALL_VPNCLIENT_DIR=\$\(DESTDIR\)/g" linux_32bit.mak
sed -i -e "s/^INSTALL_VPNCMD_DIR=/INSTALL_VPNCMD_DIR=\$\(DESTDIR\)/g" linux_32bit.mak

## for the echos
sed -i -e "s/^\techo/#\techo/g" linux_32bit.mak
sed -i -e "s/^\tchmod/#\tchmod/g" linux_32bit.mak

## vpnserver
sed -i -e "s/\@mkdir -p \$(INSTALL_VPNSERVER_DIR)/install -d \$(INSTALL_VPNSERVER_DIR)/g" linux_32bit.mak
sed -i -e "s/cp bin\/vpnserver\/hamcore.se2 \$(INSTALL_VPNSERVER_DIR)hamcore.se2/install -m 600 bin\/vpnserver\/hamcore.se2 \$(INSTALL_VPNSERVER_DIR)hamcore.se2/g" linux_32bit.mak
sed -i -e "s/cp bin\/vpnserver\/vpnserver \$(INSTALL_VPNSERVER_DIR)vpnserver/install -m 755 bin\/vpnserver\/vpnserver \$(INSTALL_VPNSERVER_DIR)vpnserver/g" linux_32bit.mak

## vpnbridge
sed -i -e "s/\@mkdir -p \$(INSTALL_VPNBRIDGE_DIR)/install -d \$(INSTALL_VPNBRIDGE_DIR)/g" linux_32bit.mak
sed -i -e "s/cp bin\/vpnbridge\/hamcore.se2 \$(INSTALL_VPNBRIDGE_DIR)hamcore.se2/install -m 600 bin\/vpnbridge\/hamcore.se2 \$(INSTALL_VPNBRIDGE_DIR)hamcore.se2/g" linux_32bit.mak
sed -i -e "s/cp bin\/vpnbridge\/vpnbridge \$(INSTALL_VPNBRIDGE_DIR)vpnbridge/install -m 755 bin\/vpnbridge\/vpnbridge \$(INSTALL_VPNBRIDGE_DIR)vpnbridge/g" linux_32bit.mak

## vpnclient
sed -i -e "s/\@mkdir -p \$(INSTALL_VPNCLIENT_DIR)/install -d \$(INSTALL_VPNCLIENT_DIR)/g" linux_32bit.mak
sed -i -e "s/cp bin\/vpnclient\/hamcore.se2 \$(INSTALL_VPNCLIENT_DIR)hamcore.se2/install -m 600 bin\/vpnclient\/hamcore.se2 \$(INSTALL_VPNCLIENT_DIR)hamcore.se2/g" linux_32bit.mak
sed -i -e "s/cp bin\/vpnclient\/vpnclient \$(INSTALL_VPNCLIENT_DIR)vpnclient/install -m 755 bin\/vpnclient\/vpnclient \$(INSTALL_VPNCLIENT_DIR)vpnclient/g" linux_32bit.mak

## vpncmd
sed -i -e "s/\@mkdir -p \$(INSTALL_VPNCMD_DIR)/install -d \$(INSTALL_VPNCMD_DIR)/g" linux_32bit.mak
sed -i -e "s/cp bin\/vpncmd\/hamcore.se2 \$(INSTALL_VPNCMD_DIR)hamcore.se2/install -m 600 bin\/vpncmd\/hamcore.se2 \$(INSTALL_VPNCMD_DIR)hamcore.se2/g" linux_32bit.mak
sed -i -e "s/cp bin\/vpncmd\/vpncmd \$(INSTALL_VPNCMD_DIR)vpncmd/install -m 755 bin\/vpncmd\/vpncmd \$(INSTALL_VPNCMD_DIR)vpncmd/g" linux_32bit.mak

# --------------------------------------------------

# 64-bit
sed -i -e "s/^INSTALL_BINDIR=/INSTALL_BINDIR=\$\(DESTDIR\)/g" linux_64bit.mak
sed -i -e "s/^INSTALL_VPNSERVER_DIR=/INSTALL_VPNSERVER_DIR=\$\(DESTDIR\)/g" linux_64bit.mak
sed -i -e "s/^INSTALL_VPNBRIDGE_DIR=/INSTALL_VPNBRIDGE_DIR=\$\(DESTDIR\)/g" linux_64bit.mak
sed -i -e "s/^INSTALL_VPNCLIENT_DIR=/INSTALL_VPNCLIENT_DIR=\$\(DESTDIR\)/g" linux_64bit.mak
sed -i -e "s/^INSTALL_VPNCMD_DIR=/INSTALL_VPNCMD_DIR=\$\(DESTDIR\)/g" linux_64bit.mak

## for the echos
sed -i -e "s/^\techo/#\techo/g" linux_64bit.mak
sed -i -e "s/^\tchmod/#\tchmod/g" linux_64bit.mak

## vpnserver
sed -i -e "s/\@mkdir -p \$(INSTALL_VPNSERVER_DIR)/install -d \$(INSTALL_VPNSERVER_DIR)/g" linux_64bit.mak
sed -i -e "s/cp bin\/vpnserver\/hamcore.se2 \$(INSTALL_VPNSERVER_DIR)hamcore.se2/install -m 600 bin\/vpnserver\/hamcore.se2 \$(INSTALL_VPNSERVER_DIR)hamcore.se2/g" linux_64bit.mak
sed -i -e "s/cp bin\/vpnserver\/vpnserver \$(INSTALL_VPNSERVER_DIR)vpnserver/install -m 755 bin\/vpnserver\/vpnserver \$(INSTALL_VPNSERVER_DIR)vpnserver/g" linux_64bit.mak

## vpnbridge
sed -i -e "s/\@mkdir -p \$(INSTALL_VPNBRIDGE_DIR)/install -d \$(INSTALL_VPNBRIDGE_DIR)/g" linux_64bit.mak
sed -i -e "s/cp bin\/vpnbridge\/hamcore.se2 \$(INSTALL_VPNBRIDGE_DIR)hamcore.se2/install -m 600 bin\/vpnbridge\/hamcore.se2 \$(INSTALL_VPNBRIDGE_DIR)hamcore.se2/g" linux_64bit.mak
sed -i -e "s/cp bin\/vpnbridge\/vpnbridge \$(INSTALL_VPNBRIDGE_DIR)vpnbridge/install -m 755 bin\/vpnbridge\/vpnbridge \$(INSTALL_VPNBRIDGE_DIR)vpnbridge/g" linux_64bit.mak

## vpnclient
sed -i -e "s/\@mkdir -p \$(INSTALL_VPNCLIENT_DIR)/install -d \$(INSTALL_VPNCLIENT_DIR)/g" linux_64bit.mak
sed -i -e "s/cp bin\/vpnclient\/hamcore.se2 \$(INSTALL_VPNCLIENT_DIR)hamcore.se2/install -m 600 bin\/vpnclient\/hamcore.se2 \$(INSTALL_VPNCLIENT_DIR)hamcore.se2/g" linux_64bit.mak
sed -i -e "s/cp bin\/vpnclient\/vpnclient \$(INSTALL_VPNCLIENT_DIR)vpnclient/install -m 755 bin\/vpnclient\/vpnclient \$(INSTALL_VPNCLIENT_DIR)vpnclient/g" linux_64bit.mak

## vpncmd
sed -i -e "s/\@mkdir -p \$(INSTALL_VPNCMD_DIR)/install -d \$(INSTALL_VPNCMD_DIR)/g" linux_64bit.mak
sed -i -e "s/cp bin\/vpncmd\/hamcore.se2 \$(INSTALL_VPNCMD_DIR)hamcore.se2/install -m 600 bin\/vpncmd\/hamcore.se2 \$(INSTALL_VPNCMD_DIR)hamcore.se2/g" linux_64bit.mak
sed -i -e "s/cp bin\/vpncmd\/vpncmd \$(INSTALL_VPNCMD_DIR)vpncmd/install -m 755 bin\/vpncmd\/vpncmd \$(INSTALL_VPNCMD_DIR)vpncmd/g" linux_64bit.mak

