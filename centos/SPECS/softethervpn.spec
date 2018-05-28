%define majorversion 5
%define minorversion 01
%define buildversion 9657
%define dateversion 2018.01.14
%define buildrelease unstable

Name:           softethervpn
Version:        %{majorversion}.%{minorversion}.%{buildversion}
Release:        2%{?dist}
Summary:        An Open-Source Free Cross-platform Multi-protocol VPN Program

Group:          Applications/Internet
License:        GPLv2
URL:            http://www.softether.org/
Source0:        http://www.softether-download.com/files/softether/v%{majorversion}.%{minorversion}-%{buildversion}-%{buildrelease}-%{dateversion}-tree/Source_Code/softether-src-v%{majorversion}.%{minorversion}-%{buildversion}-%{buildrelease}.tar.gz

BuildRequires:  ncurses-devel
BuildRequires:  openssl-devel
BuildRequires:  readline-devel

%if 0%{?el6}%{?el5}
Requires(post)  : /sbin/chkconfig
Requires(preun) : /sbin/chkconfig
Requires(preun) : /sbin/service
%endif
%if 0%{?rhel} >= 7
Requires(post)  : systemd
Requires(preun) : systemd
%endif

%description
SoftEther VPN is one of the world's most powerful and easy-to-use multi-protocol VPN software. It runs on Windows, Linux, Mac, FreeBSD, and Solaris.

%prep
%setup -q -n v%{majorversion}.%{minorversion}-%{buildversion}

%build
%ifarch i386 i686
cp %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/centos/SOURCES/linux_32bit.mak Makefile
%else
cp %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/centos/SOURCES/linux_64bit.mak Makefile
%endif
make

%install
#rm -rf $RPM_BUILD_ROOT
%make_install
install -m 755 -d %{buildroot}/usr/bin/
install -m 755 -d %{buildroot}%{_initrddir}
install -m 755 -d %{buildroot}%{_unitdir}
install -m 755 %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/centos/SOURCES/scripts/vpnserver  %{buildroot}/usr/bin/vpnserver
install -m 755 %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/centos/SOURCES/scripts/vpnbridge  %{buildroot}/usr/bin/vpnbridge
install -m 755 %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/centos/SOURCES/scripts/vpnclient  %{buildroot}/usr/bin/vpnclient
install -m 755 %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/centos/SOURCES/scripts/vpncmd  %{buildroot}/usr/bin/vpncmd
%if 0%{?el6}%{?el5}
install -m 755 %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/centos/SOURCES/init.d/vpnserver %{buildroot}%{_initrddir}/vpnserver
%endif
%if 0%{?el7}%{?fedora}
install -m 755 %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/systemd/softether-vpnbridge.service %{buildroot}%{_unitdir}/softether-vpnbridge.service
install -m 755 %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/systemd/softether-vpnclient.service %{buildroot}%{_unitdir}/softether-vpnclient.service
install -m 755 %{_builddir}/v%{majorversion}.%{minorversion}-%{buildversion}/systemd/softether-vpnserver.service %{buildroot}%{_unitdir}/softether-vpnserver.service
%endif
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
%if 0%{?el6}%{?el5}
%{_initddir}/vpnserver
%endif
%if 0%{?el7}%{?fedora}
%{_unitdir}/*
%endif

%doc AUTHORS.TXT BUILD_UNIX.TXT BUILD_WINDOWS.TXT ChangeLog ChangeLog.txt LICENSE LICENSE.TXT README README.TXT THIRD_PARTY.TXT WARNING.TXT
%post
%if 0%{?el6}%{?el5}
/sbin/chkconfig --add vpnserver
%endif
%if 0%{?el7}%{?fedora}
%systemd_post urbackup-server.service
%endif

#%postun
#if [ "$1" -ge "1" ]; then
#       /sbin/service vpnserver condrestart >/dev/null 2>&1 || :
#fi

%preun
%if 0%{?el6}%{?el5}
if [ $1 -eq 0 ]
  then
        /sbin/service vpnserver stop >/dev/null 2>&1
        /sbin/chkconfig --del vpnserver
fi
%endif
%if 0%{?el7}%{?fedora}
%systemd_preun vpnserver.service
%endif


%changelog

* Thu Dec 14 2017 Quintin Beukes <github.com@last.za.net> - 4.23-9647
- Update upstream to 4.23-9647

* Tue Feb 14 2017 Oleg Zaitsev <me@ozaitsev.ru> - 4.22.9634-1
- Update upstream to 4.22.9634-beta
- More macrofication
- spec modified for building for several releases (i.e. EL5, EL6, Fedora)

* Wed Sep 30 2015 Jeff Tang <mrjefftang@gmail.com> - 4.19.9582-1
- Update upstream to 4.19.9582-beta

* Wed Sep 30 2015 Jeff Tang <mrjefftang@gmail.com> - 4.19.9577-1
- Update upstream to 4.19.9577

* Wed Jan 29 2014 Dexter Ang <thepoch@gmail.com> - 4.04.9412-2
- Made initscript more Fedora/RH-like.
- initscript currently using killall. Need to fix this.

* Tue Jan 21 2014 Dexter Ang <thepoch@gmail.com>
- Initial release
