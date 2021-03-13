This document describes how to build SoftEtherVPN for UNIX based Operating systems

- [Requirements](#requirements)
  * [Install requirements on Centos/RedHat](#install-requirements-on-centosredhat)
  * [Install Requirements on Debian/Ubuntu](#install-requirements-on-debianubuntu)
  * [Install Requirements on macOS](#install-requirements-on-macos)
- [Build from source code and install](#build-from-source-code-and-install)
- [Additional Build Options](#additional-build-options)
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

- [CMake](https://cmake.org)
- C compiler (GCC, Clang, etc)
- C Library (BSD libc, GNU libc, musl libc, etc)
- POSIX threads library (pthread)
- OpenSSL or LibreSSL (crypto, ssl)
- make (GNU make, BSD make, etc)
- libiconv
- readline
- ncurses

## Install requirements on Centos/RedHat

```bash
sudo yum -y groupinstall "Development Tools"
sudo yum -y install cmake ncurses-devel openssl-devel libsodium-devel readline-devel zlib-devel
```

## Install requirements on Debian/Ubuntu
```bash
sudo apt -y install cmake gcc g++ make libncurses5-dev libssl-dev libsodium-dev libreadline-dev zlib1g-dev
```

## Install requirements on macOS
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
brew install cmake openssl libsodium readline
```

# Build from source code and install

To build the programs from the source code, run the following commands:

```bash
git clone https://github.com/SoftEtherVPN/SoftEtherVPN.git
cd SoftEtherVPN
git submodule init && git submodule update
./configure
make -C build
make -C build install
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
make -C build
make -C build install
```

Building without USE_MUSL environment variable set compiles, but produced executables exhibit bad run-time behaviour.

# Additional Build Options

There are some additional build options useful if you're a distro package maintainer and creating a package of SoftEther VPN. It is recommended that you only specify these options when you understand what happens.

## Specify log, config, PID directories

By default, SoftEther VPN writes out all files such as logs, config files, PID files under the same directory as `vpnserver`, `vpnbridge`, `vpnclient` executables. This behaviour is suitable when [using SoftEther without installation](#using-softether-without-installation) however not appropriate using with installation.
Usually PID files are to put in `/var/run` or `/run`. Logs are `/var/log`. Other variable state information files including config files are `/var/lib` or `/var/db`.

These directories can be changed at compile-time by specifying via CMake variables.
* `SE_PIDDIR` - PID directory
* `SE_LOGDIR` - root log directory
* `SE_DBDIR`  - config files and variable state directory

To specify directories, perform `./configure` like below.

```bash
CMAKE_FLAGS="-DSE_PIDDIR=/run/softether -DSE_LOGDIR=/var/log/softether -DSE_DBDIR=/var/lib/softether" ./configure
```

Please note that these directories are not created automatically after installation. Make sure to create these directories before starting SoftEther VPN Server, Bridge or Client.

## Build without [cpu_features](https://github.com/google/cpu_features)

SoftEther VPN uses cpu_features library to retrieve CPU features such as available processor instructions. However, cpu_features is not available on some architectures. Whether to build with cpu_features is auto detected but autodetection is not so smart.

If you want to build without cpu_features explicitly, perform `./configure` like below.

```bash
CMAKE_FLAGS="-DSKIP_CPU_FEATURES" ./configure
```

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
from https://www.softether-download.com/.


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
from https://www.softether-download.com/.


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
from https://www.softether-download.com/.


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
https://www.softether.org/
