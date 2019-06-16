This document describes how to build SoftEtherVPN for UNIX based Operating systems

- [Requirements](#requirements)
  * [Install requirements on Centos/RedHat](#install-requirements-on-centosredhat)
  * [Install Requirements on Debian/Ubuntu](#install-requirements-on-debianubuntu)
  * [Install Requirements on macOS](#install-requirements-on-macos)
- [Build from source code and install](#build-from-source-code-and-install)
- [How to Run SoftEther](#how-to-run-softether)
  * [Start/Stop SoftEther VPN Server](#startstop-softether-vpn-server)
  * [Start/Stop SoftEther VPN Bridge](#startstop-softether-vpn-bridge)
  * [Start/Stop SoftEther VPN Client](#startstop-softether-vpn-client)
- [About HTML5-based Modern Admin Console and JSON-RPC API Suite](#about-html5-based-modern-admin-console-and-json-rpc-api-suite)
  * [Built-in SoftEther VPN Server HTML5 Ajax-based Web Administration Console](#built-in-softether-vpn-server-html5-ajax-based-web-administration-console)
  * [Built-in SoftEther Server VPN JSON-RPC API Suite](#built-in-softether-server-vpn-json-rpc-api-suite)
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

## Install requirements on Debian/Ubuntu
```bash
sudo apt -y install cmake gcc g++ libncurses5-dev libreadline-dev libssl-dev make zlib1g-dev
```

## Install requirements on macOS
```bash
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew install cmake openssl readline
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


# About HTML5-based Modern Admin Console and JSON-RPC API Suite

## Built-in SoftEther VPN Server HTML5 Ajax-based Web Administration Console
We are developing the HTML5 Ajax-based Web Administration Console (currently very limited, under construction) in the embedded HTTPS server on the SoftEther VPN Server.

Access to the following URL from your favorite web browser.

```
https://<vpn_server_hostname>:<port>/admin/
```

For example if your VPN Server is running as the port 5555 on the host at 192.168.0.1, you can access to the web console by:

```
https://192.168.0.1:5555/admin/
```

Note: Your HTML5 development contribution is very appreciated. The current HTML5 pages are written by Daiyuu Nobori (the core developer of SoftEther VPN). He is obviously lack of HTML5 development ability. Please kindly consider to contribute for SoftEther VPN's development on GitHub. Your code will help every people running SoftEther VPN Server.


## Built-in SoftEther Server VPN JSON-RPC API Suite
The API Suite allows you to easily develop your original SoftEther VPN Server management application to control the VPN Server (e.g. creating users, adding Virtual Hubs, disconnecting a specified VPN sessions).

You can access to the [latest SoftEther VPN Server JSON-RPC Document on GitHub.](https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/developer_tools/vpnserver-jsonrpc-clients/)

- Almost all control APIs, which the VPN Server provides, are available as JSON-RPC API.
You can write your own VPN Server management application in your favorite languages (JavaScript, TypeScript, Java, Python, Ruby, C#, ... etc.)
- If you are planning to develop your own VPN cloud service, the JSON-RPC API is the best choice to realize the automated operations for the VPN Server.
- No need to use any specific API client library since all APIs are provided on the JSON-RPC 2.0 Specification. You can use your favorite JSON and HTTPS client library to call any of all APIs in your pure runtime environment.
- Also, the SoftEther VPN Project provides high-quality JSON-RPC client stub libraries which define all of the API client stub codes. These libraries are written in C#, JavaScript and TypeScript. The Node.js Client Library for VPN Server RPC (vpnrpc) package is also available.


# Using SoftEther without installation

You can use any SoftEtherVPN component (server, client, bridge) without installing it, if you wish so.

In this case please do not run the `make install` command after compiling the source code, and head directly to the **bin/** directory. There you will find the generated binaries for SoftEtherVPN and those could be used without installing SoftEtherVPN.

************************************
Thank You Using SoftEther VPN !
By SoftEther VPN Open-Source Project
http://www.softether.org/
