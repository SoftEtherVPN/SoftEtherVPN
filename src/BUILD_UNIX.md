This document describes how to build SoftEtherVPN for Unix based Operating systems

- [Requirements](#requirements)
  * [Install requirements on Centos/RedHat](#install-requirements-on-centosredhat)
  * [Install Requirements on Debian/Ubuntu](#install-requirements-on-debianubuntu)
- [Build from source code and install](#build-from-source-code-and-install)
- [How to Run SoftEther](#how-to-run-softether)
  * [Start/Stop SoftEther VPN Server](#startstop-softether-vpn-server)
  * [Start/Stop SoftEther VPN Bridge](#startstop-softether-vpn-bridge)
  * [Start/Stop SoftEther VPN Client](#startstop-softether-vpn-client)
- [Using SoftEther without installation.](#using-softether-without-installation)

# Requirements

You need to install the following software to build SoftEther VPN for UNIX.

- Linux, FreeBSD, Solaris or Mac OS X.
- GNU Compiler Collection (gcc) and binary utilities. ***
- GNU Make (gmake).
- GNU C Library (glibc).
- POSIX Threads (pthread).
- OpenSSL (crypto, ssl).
- libiconv.
- readline.
- ncurses.

*It has been noted that clang is also supported as an alternative to gcc.*


## Install requirements on Centos/RedHat

```bash
sudo yum -y groupinstall "Development Tools"
sudo yum -y install cmake ncurses-devel openssl-devel readline-devel zlib-devel
```

## Install Requirements on Debian/Ubuntu
```bash
sudo apt -y install cmake gcc g++ libncurses5-dev libreadline-dev libssl-dev make zlib1g-dev
```


# Build from source code and install

To build the programs from the source code, run the following commands:

```bash
git clone https://github.com/SoftEtherVPN/SoftEtherVPN.git
cd SoftEtherVPN
git submodule init && git submodule update
./configure
make -C tmp
make -C tmp install
```

This will compile and install SoftEther VPN Server, Bridge and Client binaries under your executable path.

If any error occurs, please check the above requirements.

# Build on musl-based linux 

To build the programs from the source code when using musl as libc, run the following commands:

```bash
export USE_MUSL=YES
git clone https://github.com/SoftEtherVPN/SoftEtherVPN.git
cd SoftEtherVPN
git submodule init && git submodule update
./configure
make -C tmp
make -C tmp install
```

Building without USE_MUSL environment variable set compiles, but produced executables exhibit bad run-time behaviour.

# How to Run SoftEther

## Start/Stop SoftEther VPN Server

To start the SoftEther VPN Server background service, run the following:

```bash
vpnserver start
```

To stop the service, run the following:

```bash
vpnserver stop
```

To configure the running SoftEther VPN Server service,
you can use SoftEther VPN Command Line Management Utility as following:

```bash
vpncmd
```

Or you can also use VPN Server Manager GUI Tool on other Windows PC to
connect to the VPN Server remotely. You can download the GUI Tool
from http://www.softether-download.com/.


## Start/Stop SoftEther VPN Bridge

To start the SoftEther VPN Bridge background service, run the following:

```bash
vpnbridge start
```

To stop the service, run the following:

```bash
vpnbridge stop
```

To configure the running SoftEther VPN Bridge service,
you can use SoftEther VPN Command Line Management Utility as following:

```bash
vpncmd
```

Or you can also use VPN Server Manager GUI Tool on other Windows PC to
connect to the VPN Bridge remotely. You can download the GUI Tool
from http://www.softether-download.com/.


## Start/Stop SoftEther VPN Client

To start the SoftEther VPN Client background service, run the following:

```bash
vpnclient start
```

To stop the service, run the following:

```bash
vpnclient stop
```

To configure the running SoftEther VPN Client service,
you can use SoftEther VPN Command Line Management Utility as following:

```bash
vpncmd
```

Or you can also use VPN Client Manager GUI Tool on other Windows PC to
connect to the VPN Client remotely. You can download the GUI Tool
from http://www.softether-download.com/.


# Using SoftEther without installation.

You can use any SoftEtherVPN component (server, client, bridge) without installing it, if you wish so.

In this case please do not run the `make install` command after compiling the source code, and head directly to the **bin/** directory. There you will find the generated binaries for SoftEtherVPN and those could be used without installing SoftEtherVPN.

************************************
Thank You Using SoftEther VPN !
By SoftEther VPN Open-Source Project
http://www.softether.org/
