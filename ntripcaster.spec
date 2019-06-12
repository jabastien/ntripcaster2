%define name	ntripcaster
%define version	2.0.21
%define release 1

Summary:        BKG prefessional Ntrip caster - Streaming DGPS data server
Name:           %{name}
Version:        %{version}
Release:        %{release}
Group:          Applications/Engineering
License:        GPL
URL:            http://igs.bkg.bund.de/index_ntrip.htm
Source:         %{name}-%{version}.tar.bz2
BuildRoot:      %{_tmppath}/%{name}-%{version}-root

%debug_package

%description
Ntripcaster is a streaming DGPS data server.

%prep
%setup

%build
if [ ! -f configure ]; then
  CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh --enable-fsstd
else
  %configure --enable-fsstd
fi
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install
mkdir -p $RPM_BUILD_ROOT/var/run/ntripcaster

# copy the configuration files to be the right name so that it works without 
# _having_ # to change them (though they should), and leave the defaults so 
# they don't screw with them
cp $RPM_BUILD_ROOT/etc/ntripcaster/ntripcaster.conf.dist $RPM_BUILD_ROOT/etc/ntripcaster/ntripcaster.conf
cp $RPM_BUILD_ROOT/etc/ntripcaster/groups.aut.dist $RPM_BUILD_ROOT/etc/ntripcaster/groups.aut
cp $RPM_BUILD_ROOT/etc/ntripcaster/sourcemounts.aut.dist $RPM_BUILD_ROOT/etc/ntripcaster/sourcemounts.aut
cp $RPM_BUILD_ROOT/etc/ntripcaster/clientmounts.aut.dist $RPM_BUILD_ROOT/etc/ntripcaster/clientmounts.aut
cp $RPM_BUILD_ROOT/etc/ntripcaster/users.aut.dist $RPM_BUILD_ROOT/etc/ntripcaster/users.aut
cp $RPM_BUILD_ROOT/etc/ntripcaster/sourcetable.dat.dist $RPM_BUILD_ROOT/etc/ntripcaster/sourcetable.dat
mkdir -p $RPM_BUILD_ROOT/etc/init.d
cp scripts/rcscript $RPM_BUILD_ROOT/etc/init.d/ntripcaster
ln -s /etc/init.d/ntripcaster $RPM_BUILD_ROOT//usr/sbin/rcntripcaster

%files
%defattr(-,root,root)
%doc CHANGES
%doc COPYING
%doc FAQ
%doc README
%doc NtripCaster.pdf

/usr/bin/ntripcaster
/usr/bin/casterwatch
/usr/sbin/ntripdaemon
/usr/share/ntripcaster/
/etc/ntripcaster/groups.aut.dist
/etc/ntripcaster/sourcemounts.aut.dist
/etc/ntripcaster/clientmounts.aut.dist
/etc/ntripcaster/users.aut.dist
/etc/ntripcaster/ntripcaster.conf.dist
/etc/ntripcaster/sourcetable.dat.dist
%config(noreplace) /etc/ntripcaster/groups.aut
%config(noreplace) /etc/ntripcaster/sourcemounts.aut
%config(noreplace) /etc/ntripcaster/clientmounts.aut
%config(noreplace) /etc/ntripcaster/users.aut
%config(noreplace) /etc/ntripcaster/ntripcaster.conf
%config(noreplace) /etc/ntripcaster/sourcetable.dat
%dir /etc/ntripcaster
%defattr(755,root,root)
%dir /var/run/ntripcaster
%dir /var/log/ntripcaster
/etc/init.d/ntripcaster
/usr/sbin/rcntripcaster

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%changelog
* Thu Apr 8 2010 Dirk Stöcker <stoecker@alberding.eu> 2.0.10
- update for 2.0.10

* Tue Mar 21 2000 Jeremy Katz <katzj@ntripcaster.org>
- clean up the spec file a little

* Thu Dec 9 1999 Jeremy Katz <katzj@ntripcaster.org>
- First official rpm build, using 2.0.0-beta