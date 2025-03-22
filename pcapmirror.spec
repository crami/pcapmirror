Name:     pcapmirror
Version:  0.2
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
%license LICENSE
%doc README.md

%changelog
* %(date +%s) - 0.2-1
- Initial release of pcapmirror
