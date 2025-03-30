Name:     pcapmirror
Version:  0.5
Release:  %(perl -e 'print time()')%{?dist}
Summary:  A simple packet capture mirror
License:  BSD 3-Clause License
URL:      https://git.freestone.net/cramer/pcapmirror
Source:   https://git.freestone.net/cramer/pcapmirror/-/archive/v%version/pcapmirror-v%version.tar.gz
BuildRequires:   gcc
BuildRequires:   make
BuildRequires:   libpcap-devel

%description
pcapmirror is a command-line tool for capturing and mirroring network traffic using TZSP encapsulation. It leverages the `libpcap` library for packet capture and supports BPF syntax for filtering traffic.

%build
%make_build

%install
%make_install

%files
%{_bindir}/pcapmirror
%{_mandir}/man8/pcapmirror.8.gz
%license LICENSE
%doc README.md


%changelog
* Sat Mar 29 2025 Matthias Cramer <cramer@freesone.net> 0.5-1
- new option -c to count matching packets (overrides verbose mode)
- reworked packet decoder to also decode arp, vlan and qinq packets
- well known protocols numbers are now decoded
- works now on MacOS and OpenBSD
* Mon Mar 24 2025 Matthias Cramer <cramer@freesone.net> 0.4-1
- IPv6 support for remote destination
- remote destination can now also be hostname
- added option to enforce IPv4 and IPv6 for remote destination
* Sat Mar 22 2025 Matthias Cramer <cramer@freesone.net> 0.3-1
- added manpage
* Sat Mar 22 2025 Matthias Cramer <cramer@freesone.net> 0.2-1
- Initial release of pcapmirror
