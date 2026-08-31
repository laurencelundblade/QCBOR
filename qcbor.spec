# Reference spec for QCBOR. The authoritative Fedora package is maintained
# in Fedora dist-git; this copy may lag. QCBOR does not publish official
# binary packages — see README. Build from source via CMake.

# Guidelines from https://docs.fedoraproject.org/en-US/packaging-guidelines/CMake/

# Special credit to Brian Sipos even though his PR wasn't merged

Name: qcbor
Version: 1.7.0
Release: 1%{?dist}
Summary: A CBOR encoder/decoder library
URL: https://github.com/laurencelundblade/QCBOR
License: BSD-3-Clause
Source0: %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires: cmake
BuildRequires: gcc
BuildRequires: doxygen
BuildRequires: coreutils

%description
Comprehensive, powerful, commercial-quality CBOR encoder and decoder
that is still suited for small devices.


%package devel
Summary: Development files for the QCBOR library
Requires: %{name}%{?_isa} = %{version}-%{release}
%description devel
Development files needed to build and link to the QCBOR library.

%package doc
Summary: API documentation for QCBOR library
Requires: %{name}%{?_isa} = %{version}-%{release}
%description doc
API documentation in the form of Docbook XML generated
from the API with Doxygen.


%prep
%setup -q -n QCBOR-%{version}


%build
%cmake -DBUILD_QCBOR_TEST=APP
%cmake_build

pushd doxygen
sed -i 's|GENERATE_DOCBOOK.*=.*|GENERATE_DOCBOOK = YES|g' Doxyfile
sed -i 's|GENERATE_HTML.*=.*|GENERATE_HTML = NO|g' Doxyfile
sed -i 's|GENERATE_MAN.*=.*|GENERATE_MAN = NO|g' Doxyfile
doxygen
popd


%install
%cmake_install

install -m644 doxygen/docbook/*.xml -D -t %{buildroot}%{_datadir}/help/en/qcbor/


%check
%ctest


%files
%license LICENSE
%doc README.md
%{_libdir}/libqcbor.so.*

%files devel
%license LICENSE
%doc README.md
%{_includedir}/qcbor/
%{_libdir}/libqcbor.so
%{_libdir}/cmake/qcbor/
%{_libdir}/pkgconfig/qcbor.pc

%files doc
%license LICENSE
%doc %lang(en) %{_datadir}/help/en/qcbor/


%changelog
* Tue Aug 25 2026 Laurence Lundblade <lgl@island-resort.com> - 1.7.0-1
- Update to 1.7.0; see CHANGELOG.md for release notes
- SOVERSION bumped to 2; dependent packages must be rebuilt

* Tue Jun 09 2026 Brian Sipos <brian.sipos@gmail.com> - 1.6.1-2
- Import into Fedora

* Fri Mar 20 2026 Laurence Lundblade <lgl@island-resort.com> - 1.6.1-1
- Modernize cmake build and install
- Minor QCBORDecode_EnteryArray() error handling bugfix

* Wed Nov 12 2025 Laurence Lundblade <lgl@island-resort.com> - 1.6.0-1
- Better Windows/MSVC support
- Bug fix for GetArray() and GetMap()
- Fix gcc warnings
- Bug fix for OpenBstr on empty map at end of input
- Bug fix for floating-point NaN payload conversion for preferred serialization
- Don't use strcpy()

* Mon Jun 16 2025 Laurence Lundblade <lgl@island-resort.com> - 1.5.3-1
- Bug fix for GetArray() from empty map
- Increase test coverage
- Documentation improvements

* Mon Jun 16 2025 Laurence Lundblade <lgl@island-resort.com> - 1.5.2-1
- Bug fix for QCBORDecode_GetMap() and QCBORDecode_GetArray()
- Fix warning for compilers compliant with C23 standard
- Minor documentation fix
- Fix for embedded platforms with partial implementations of llround()

* Mon Jan 8 2024 Laurence Lundblade <lgl@island-resort.com> - 1.5.1-1
- Initial library RPM packaging.
