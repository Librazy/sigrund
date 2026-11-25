Name:           sigrun
Version:        %{package_version}
Release:        %{package_release}%{?dist}
Summary:        Client for signed command elevation
License:        MIT
URL:            https://github.com/Librazy/sigrund
Source0:        payload.tar.gz
BuildRequires:  selinux-policy-devel
BuildRequires:  selinux-policy-targeted
BuildRequires:  container-selinux

%global selinuxtype targeted

# Cargo has already built the locked release binaries in this distribution.
%global debug_package %{nil}

%description
Unprivileged requester for sigrund. Submits commands for SSH-backed approval
and relays command output and exit status. The daemon is installed separately.

%package -n sigrund
Summary:        Daemon and operator tools for signed command elevation
Requires:       systemd
Requires:       openssh-clients
Suggests:       sigrund-selinux = %{version}-%{release}

%description -n sigrund
Policy enforcement, root-TTY SSH approval, one-time authorization, local audit
and supervised execution. Installation does not provision or start the daemon.

%package -n sigrund-selinux
Summary:        SELinux policy for sigrund host and namespace execution
BuildArch:      noarch
Requires:       sigrund = %{version}-%{release}
Requires:       selinux-policy-%{selinuxtype} >= %{_selinux_policy_version}
Requires:       policycoreutils
Requires(pre):  libselinux-utils
Requires(preun): libselinux-utils
%{?selinux_requires_min}

%description -n sigrund-selinux
Precompiled daemon, workload and restricted requester policy. Installation loads
the modules and labels the packaged paths; it does not enable namespace rules or
restart the daemon. Stop the daemon before installing or updating this policy.

%package -n sigrund-selinux-podman
Summary:        Optional SELinux policy for the sigrund Podman adapter
BuildArch:      noarch
Requires:       sigrund-selinux = %{version}-%{release}
Requires:       container-selinux
Requires:       policycoreutils
Requires(pre):  libselinux-utils
Requires(preun): libselinux-utils
%{?selinux_requires_min}

%description -n sigrund-selinux-podman
Precompiled policy allowing the daemon to access the local rootful Podman API.
This package does not install or start Podman, or register execution targets.

%prep
%setup -q -c -T
tar -xzf %{SOURCE0}

%build

%install
mkdir -p %{buildroot}
cp -a sigrun/. %{buildroot}/
cp -a sigrund/. %{buildroot}/
cp -a sigrund-selinux/. %{buildroot}/
cp -a sigrund-selinux-podman/. %{buildroot}/

%pre -n sigrund-selinux
%selinux_relabel_pre -s %{selinuxtype}

%post -n sigrund-selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/sigrund_daemon.pp %{_datadir}/selinux/packages/%{selinuxtype}/sigrund_workload.pp %{_datadir}/selinux/packages/%{selinuxtype}/sigrund_requester.pp

%preun -n sigrund-selinux
%selinux_relabel_pre -s %{selinuxtype}

%postun -n sigrund-selinux
if [ "$1" -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} sigrund_requester sigrund_workload sigrund_daemon
    %selinux_relabel_post -s %{selinuxtype}
fi

%posttrans -n sigrund-selinux
%selinux_relabel_post -s %{selinuxtype}

%pre -n sigrund-selinux-podman
%selinux_relabel_pre -s %{selinuxtype}

%post -n sigrund-selinux-podman
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/sigrund_podman.pp

%preun -n sigrund-selinux-podman
%selinux_relabel_pre -s %{selinuxtype}

%postun -n sigrund-selinux-podman
if [ "$1" -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} sigrund_podman
    %selinux_relabel_post -s %{selinuxtype}
fi

%posttrans -n sigrund-selinux-podman
%selinux_relabel_post -s %{selinuxtype}

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
/usr/bin/sigrund-approve-tui
/usr/bin/sigrundctl
/usr/bin/sigrund-anchor
/usr/libexec/sigrund
/usr/lib/systemd/system/sigrund.service
%dir /etc/sigrund
%doc /usr/share/doc/sigrund
%license /usr/share/licenses/sigrund/LICENSE

%files -n sigrund-selinux
%{_datadir}/selinux/devel/include/apps/sigrund_custom.if
%{_datadir}/selinux/packages/%{selinuxtype}/sigrund_daemon.pp
%{_datadir}/selinux/packages/%{selinuxtype}/sigrund_workload.pp
%{_datadir}/selinux/packages/%{selinuxtype}/sigrund_requester.pp
%doc /usr/share/doc/sigrund-selinux
%license /usr/share/licenses/sigrund-selinux/LICENSE

%files -n sigrund-selinux-podman
%{_datadir}/selinux/packages/%{selinuxtype}/sigrund_podman.pp
%doc /usr/share/doc/sigrund-selinux-podman
%license /usr/share/licenses/sigrund-selinux-podman/LICENSE
