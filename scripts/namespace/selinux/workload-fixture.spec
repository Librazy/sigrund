Name: sigrund-workload-fixture
Version: 1
Release: 1
Summary: Disposable workload package installation fixture
License: MIT
BuildArch: noarch
%description
Disposable data-only package, without scripts or dependencies.
%install
mkdir -p %{buildroot}/usr/share/sigrund-workload-fixture
printf 'installed by an approved workload\n' > %{buildroot}/usr/share/sigrund-workload-fixture/installed.txt
%files
/usr/share/sigrund-workload-fixture
