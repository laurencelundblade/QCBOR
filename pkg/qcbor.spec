# Guidelines from https://docs.fedoraproject.org/en-US/packaging-guidelines/CMake/

Name: qcbor
Version: 1.5.0
Release: 0%{?dist}
Summary: A CBOR encoder/decoder library
URL: https://github.com/laurencelundblade/QCBOR
License: BSD-3-Clause
Source0: %{URL}/archive/refs/tags/v1.5.tar.gz

BuildRequires: cmake
BuildRequires: gcc

%description
Comprehensive, powerful, commercial-quality CBOR encoder and decoder
that is still suited for small devices. 


%package devel
Summary: Development files for the QCBOR library
Requires: %{name}%{?_isa} = %{version}
%description devel
Development files needed to build and link to the QCBOR library.


%prep
%setup -q -n QCBOR-1.5
%cmake -DBUILD_QCBOR_TEST=APP


%build
%cmake_build 

%install
%cmake_install


%check
# TODO use %ctest when supported by QCBOR config
./%{_vpath_builddir}/test/qcbortest


%files
%license LICENSE
%doc README.md
%{_libdir}/*.so.*

%files devel
%license LICENSE
%doc README.md
%{_includedir}/qcbor
%{_libdir}/*.so


%changelog
* Fri Dec 20 2024 Laurence Lundblade <lgl@island-resort.com> - 1.5.0-0
- Initial library RPM packaging.
