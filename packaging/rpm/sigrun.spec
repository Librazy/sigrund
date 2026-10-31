Name:           sigrun
Version:        %{package_version}
Release:        %{package_release}%{?dist}
Summary:        Client for signed command elevation
License:        MIT
URL:            https://github.com/Librazy/sigrund
Source0:        payload.tar.gz

# Cargo has already built the locked release binaries in this distribution.
%global debug_package %{nil}

%description
Unprivileged requester for sigrund. Submits commands for SSH-backed approval
and relays command output and exit status. The daemon is installed separately.

%package -n sigrund
Summary:        Daemon and operator tools for signed command elevation
Requires:       systemd
Requires:       openssh-clients

%description -n sigrund
Policy enforcement, root-TTY SSH approval, one-time authorization, local audit
and supervised execution. Installation does not provision or start the daemon.

%prep
%setup -q -c -T
tar -xzf %{SOURCE0}

%build

%install
mkdir -p %{buildroot}
cp -a sigrun/. %{buildroot}/
cp -a sigrund/. %{buildroot}/

%post -n sigrund
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi

%preun -n sigrund
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl disable --now sigrund.service || :
fi

%postun -n sigrund
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi

%files
/usr/bin/sigrun
%doc /usr/share/doc/sigrun/README.md
%license /usr/share/licenses/sigrun/LICENSE

%files -n sigrund
/usr/bin/sigrund-approve
/usr/bin/sigrundctl
/usr/libexec/sigrund
/usr/lib/systemd/system/sigrund.service
%dir /etc/sigrund
%doc /usr/share/doc/sigrund
%license /usr/share/licenses/sigrund/LICENSE
