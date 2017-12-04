How to build SoftEther VPN for UNIX
===================================


Requirements
------------

You need to install the following software to build SoftEther VPN for UNIX.

- Linux, FreeBSD, Solaris or Mac OS X.
- GNU Compiler Collectipon (gcc) and binary utilities.
- GNU Make (gmake).
- GNU C Library (glibc).
- POSIX Threads (pthread).
- OpenSSL (crypto, ssl).
- libiconv.
- readline.
- ncurses.

For example, the following commands help you to install the above programs
on Fedora or CentOS Linux:
```
$ yum -y groupinstall "Development Tools"
$ yum -y install readline-devel ncurses-devel openssl-devel
```


How to Build
------------

To build the programs from the source code, run the following commands:

```
$ ./configure
$ make
```

If any error occurs, please check the above requirements.


How to Install SoftEther VPN Server, Bridge or Client
-----------------------------------------------------

To install the vpnserver, vpnbridge and vpnclient programs into the
/usr/bin directory, run the following as the root user:

```
# make install
```

After the installation will complete successfully:

- Execute 'vpnserver start' to run the SoftEther VPN Server background service.
- Execute 'vpnbridge start' to run the SoftEther VPN Bridge background service.
- Execute 'vpnclient start' to run the SoftEther VPN Client background service.
- Execute 'vpncmd' to run SoftEther VPN Command-Line Utility to configure
  VPN Server, VPN Bridge or VPN Client.

- You can also use VPN Server/Client Manager GUI Tool on other Windows PC to
  connect to VPN services remotely.
  You can download the GUI Tools from http://www.softether-download.com/.


How to Run SoftEther VPN Server for Test
----------------------------------------

To start the SoftEther VPN Server background service, run the following:

```
$ bin/vpnserver/vpnserver start
```

To stop the service, run the following:

```
$ bin/vpnserver/vpnserver stop
```

To configure the running SoftEther VPN Server service,
you can use SoftEther VPN Command Line Management Utility as following:

```
$ bin/vpncmd/vpncmd
```

Or you can also use VPN Server Manager GUI Tool on other Windows PC to
connect to the VPN Server remotely. You can download the GUI Tool
from http://www.softether-download.com/.


How to Run SoftEther VPN Bridge for Test
----------------------------------------

To start the SoftEther VPN Bridge background service, run the following:

```
$ bin/vpnbridge/vpnbridge start
```

To stop the service, run the following:

```
$ bin/vpnbridge/vpnbridge stop
```

To configure the running SoftEther VPN Bridge service,
you can use SoftEther VPN Command Line Management Utility as following:

```
$ bin/vpncmd/vpncmd
```

Or you can also use VPN Server Manager GUI Tool on other Windows PC to
connect to the VPN Bridge remotely. You can download the GUI Tool
from http://www.softether-download.com/.


How to Run SoftEther VPN Client for Test
----------------------------------------

To start the SoftEther VPN Client background service, run the following:

```
$ bin/vpnclient/vpnclient start
```

To stop the service, run the following:

```
$ bin/vpnclient/vpnclient stop
```

To configure the running SoftEther VPN Client service,
you can use SoftEther VPN Command Line Management Utility as following:

```
$ bin/vpncmd/vpncmd
```

Or you can also use VPN Client Manager GUI Tool on other Windows PC to
connect to the VPN Client remotely. You can download the GUI Tool
from http://www.softether-download.com/.


************************************
Thank You Using SoftEther VPN !
By SoftEther VPN Open-Source Project
http://www.softether.org/
