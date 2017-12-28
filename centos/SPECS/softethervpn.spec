%define majorversion 4
%define minorversion 23
%define buildversion 9647
%define dateversion 2017.10.18
%define buildrelease beta

Name:           softethervpn
Version:        %{majorversion}.%{minorversion}.%{buildversion}
Release:        1%{?dist}
Summary:        An Open-Source Free Cross-platform Multi-protocol VPN Program

Group:          Applications/Internet
License:        GPLv2
URL:            http://www.softether.org/
Source0:        http://www.softether-download.com/files/softether/v%{majorversion}.%{minorversion}-%{buildversion}-%{buildrelease}-%{dateversion}-tree/Source_Code/softether-src-v%{majorversion}.%{minorversion}-%{buildversion}-%{buildrelease}.tar.gz

BuildRequires:  ncurses-devel
BuildRequires:	openssl-devel
BuildRequires:	readline-devel

Requires(post):		chkconfig
Requires(postun):	initscripts
Requires(preun):	chkconfig
Requires(preun):	initscripts

%description
SoftEther VPN is one of the world's most powerful and easy-to-use multi-protocol VPN software. It runs on Windows, Linux, Mac, FreeBSD, and Solaris.

%prep
%setup -q -n v%{majorversion}.%{minorversion}-%{buildversion}

%build
%ifarch i386 i686
cp $RPM_SOURCE_DIR/linux_32bit.mak Makefile
%else
cp $RPM_SOURCE_DIR/linux_64bit.mak Makefile
%endif
make

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
install -m 755 -d $RPM_BUILD_ROOT/usr/bin/
install -m 755 -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m 755 $RPM_SOURCE_DIR/scripts/vpnserver $RPM_BUILD_ROOT/usr/bin/vpnserver
install -m 755 $RPM_SOURCE_DIR/scripts/vpnbridge $RPM_BUILD_ROOT/usr/bin/vpnbridge
install -m 755 $RPM_SOURCE_DIR/scripts/vpnclient $RPM_BUILD_ROOT/usr/bin/vpnclient
install -m 755 $RPM_SOURCE_DIR/scripts/vpncmd $RPM_BUILD_ROOT/usr/bin/vpncmd
install -m 755 $RPM_SOURCE_DIR/init.d/vpnserver $RPM_BUILD_ROOT/etc/rc.d/init.d/vpnserver

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_usr}/bin/vpnserver
%{_usr}/bin/vpnbridge
%{_usr}/bin/vpnclient
%{_usr}/bin/vpncmd
%{_usr}/vpnserver/hamcore.se2
%{_usr}/vpnserver/vpnserver
%{_usr}/vpnbridge/hamcore.se2
%{_usr}/vpnbridge/vpnbridge
%{_usr}/vpnclient/hamcore.se2
%{_usr}/vpnclient/vpnclient
%{_usr}/vpncmd/hamcore.se2
%{_usr}/vpncmd/vpncmd
%{_usr}/vpnserver/
%{_usr}/vpnbridge/
%{_usr}/vpnclient/
%{_usr}/vpncmd/
%{_initddir}/vpnserver
%doc AUTHORS.TXT BUILD_UNIX.TXT BUILD_WINDOWS.TXT ChangeLog ChangeLog.txt LICENSE LICENSE.TXT README README.TXT THIRD_PARTY.TXT WARNING.TXT

%post
/sbin/chkconfig --add vpnserver

#%postun
#if [ "$1" -ge "1" ]; then
#	/sbin/service vpnserver condrestart >/dev/null 2>&1 || :
#fi

%preun
if [ $1 -eq 0 ]; then
	/sbin/service vpnserver stop >/dev/null 2>&1
	/sbin/chkconfig --del vpnserver
fi

%changelog
* Wed Dec 18 2017 You Xiaojie <yxj790222@163.com> - 4.23.9647-1
- Upgraded OpenSSL to 1.0.2l.
- Source code is now compatible with OpenSSL 1.1.x. Supports DHE-RSA-CHACHA 20-POLY 1305 and ECDHE-RSA-CHACHA 20-POLY 1305, which are new encryption methods of TLS 1.2. (In order to use this new function, you need to recompile yourself using OpenSSL 1.1.x.)
- TrafficServer / TrafficClient function (The traffic throughput measurement function) is now multithreaded and compatible with about 10 Gbps using NIC with the RSS feature.
- Changed the default algorithm for SSL from RC4-MD5 to AES128-SHA.
- Fixed a bug that occurr wrong checksum recalculation in special case of the TCP-MSS clamp processing.
- Fixed the calculation interval of update interval of DHCP client packet issued by kernel mode virtual NAT function of SecureNAT function.
- Driver upgrade and DLL name change with Crypto ID support of USB security token.
- Fixed a problem that CPU sleep processing was not performed when the wait time of the Select () function was INFINITE on Mac OS X.
- Added the StrictSyslogDatetimeFormat flag onto the ServerConfiguration section on the VPN Server configuration file, which sets Syslog date format to RFC3164.
- Fixed wrong English in the UI.
- Using client parameter in function CtConnect
- Stop Radius Delay from counting to next_resend
- Add DH groups 2048,3072,4096 to IPSec_IKE
- Add HMAC SHA2-256, HMAC SHA2-384, HMAC SHA2-512 support
- Openvpn extend ciphers
- Fixed RSA key bits wrong calculation for certain x509 certificate
- Added support for RuToken USB key PKCS#11

* Wed Sep 30 2015 Jeff Tang <mrjefftang@gmail.com> - 4.19.9582-1
- Update upstream to 4.19.9582-beta

* Wed Sep 30 2015 Jeff Tang <mrjefftang@gmail.com> - 4.19.9577-1
- Update upstream to 4.19.9577

* Wed Jan 29 2014 Dexter Ang <thepoch@gmail.com> - 4.04.9412-2
- Made initscript more Fedora/RH-like.
- initscript currently using killall. Need to fix this.

* Tue Jan 21 2014 Dexter Ang <thepoch@gmail.com>
- Initial release

