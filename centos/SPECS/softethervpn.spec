%define majorversion 4.04
%define minorversion 9412
%define dateversion 2014.01.15

Name:           softethervpn
Version:        %{majorversion}.%{minorversion}
Release:        2%{?dist}
Summary:        An Open-Source Free Cross-platform Multi-protocol VPN Program

Group:          Applications/Internet
License:        GPLv2
URL:            http://www.softether.org/
Source0:        http://www.softether-download.com/files/softether/v%{majorversion}-%{minorversion}-rtm-%{dateversion}-tree/Source%20Code/softether-src-v%{majorversion}-%{minorversion}-rtm.tar.gz

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
%setup -q -n v%{majorversion}-%{minorversion}

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
* Wed Jan 29 2014 Dexter Ang <thepoch@gmail.com> - 4.04.9412-2
- Made initscript more Fedora/RH-like.
- initscript currently using killall. Need to fix this.

* Tue Jan 21 2014 Dexter Ang <thepoch@gmail.com>
- Initial release


