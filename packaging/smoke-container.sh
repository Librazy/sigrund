#!/bin/bash
# Runs in a fresh disposable target container, not the build container or host.
set -euo pipefail
kind=$1
scenario=${2:-combined}
case "$scenario" in
  daemon-only|combined) ;;
  selinux) [[ "$kind" == rpm ]] || exit 64 ;;
  *) exit 64 ;;
esac
assert_absent() {
  if installed "$1"; then
    echo "Unexpected installed package: $1" >&2
    exit 1
  fi
}
if [[ "$kind" == deb ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  install_packages() { apt-get install -y --no-install-recommends "$@"; }
  remove_packages() { apt-get purge -y "$@"; }
  installed() { dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -qx installed; }
  dependencies() { dpkg-deb -f "$1" Depends; }
  client_old=(/out/previous/sigrun_*.deb)
  client_new=(/out/packages/sigrun_*.deb)
  daemon_old=(/out/previous/sigrund_*.deb)
  daemon_new=(/out/packages/sigrund_*.deb)
elif [[ "$kind" == rpm ]]; then
  install_packages() { dnf install -y "$@"; }
  remove_packages() { dnf remove -y "$@"; }
  installed() { rpm -q "$1" >/dev/null 2>&1; }
  dependencies() { rpm -qp --requires "$1"; }
  client_old=(/out/previous/sigrun-[0-9]*.x86_64.rpm)
  client_new=(/out/packages/sigrun-[0-9]*.x86_64.rpm)
  daemon_old=(/out/previous/sigrund-[0-9]*.x86_64.rpm)
  daemon_new=(/out/packages/sigrund-[0-9]*.x86_64.rpm)
  policy_old=(/out/previous/sigrund-selinux-[0-9]*.noarch.rpm)
  policy_new=(/out/packages/sigrund-selinux-[0-9]*.noarch.rpm)
  podman_old=(/out/previous/sigrund-selinux-podman-[0-9]*.noarch.rpm)
  podman_new=(/out/packages/sigrund-selinux-podman-[0-9]*.noarch.rpm)
else
  exit 64
fi

cd /out/packages
sha256sum --check SHA256SUMS
client_dependencies=$(dependencies "${client_new[0]}")
if grep -E 'sigrund|systemd|openssh' <<< "$client_dependencies"; then
  echo 'Client package has an unexpected service dependency' >&2
  exit 1
fi
daemon_dependencies=$(dependencies "${daemon_new[0]}")
if grep -E '(^|[[:space:],|(])sigrun(:[[:alnum:]-]+)?([[:space:](,|<>=]|$)' <<< "$daemon_dependencies"; then
  echo 'Daemon package has an unexpected client dependency' >&2
  exit 1
fi
assert_absent sigrun
assert_absent sigrund
if [[ "$scenario" == combined ]]; then
  install_packages "${client_old[0]}"
  sigrun --help
  assert_absent sigrund
  test ! -e /usr/libexec/sigrund/sigrund
  test ! -e /usr/lib/systemd/system/sigrund.service
  install_packages "${client_new[0]}"
  sigrun --help
fi

install_packages "${daemon_old[0]}"
if [[ "$kind" == rpm ]]; then
  assert_absent sigrund-selinux
  assert_absent sigrund-selinux-podman
fi
if [[ "$scenario" != combined ]]; then
  assert_absent sigrun
  test ! -e /usr/bin/sigrun
fi
/usr/libexec/sigrund/sigrund --help
sigrund-approve --help
sigrund-anchor --help
sigrundctl --validate-uuid "$(sigrundctl uuidv7)"
systemd-analyze verify /usr/lib/systemd/system/sigrund.service
test ! -e /etc/sigrund/config.toml
test ! -e /var/lib/sigrund/host_id
test ! -e /etc/systemd/system/multi-user.target.wants/sigrund.service

has_module() {
  local modules
  modules=$(semodule -l) || exit 1
  awk -v name="$1" '$1 == name { found=1 } END { exit !found }' <<< "$modules"
}
assert_module_absent() {
  if has_module "$1"; then
    echo "Unexpected installed SELinux module: $1" >&2
    exit 1
  fi
}
if [[ "$scenario" == selinux ]]; then
  # This is an offline policy-store test. Never load the build host's kernel policy.
  if [[ -e /sys/fs/selinux/enforce ]]; then
    echo 'SELinux smoke tests require a container without an active selinuxfs' >&2
    exit 1
  fi
  install_packages "${policy_old[0]}"
  for module in sigrund_daemon sigrund_workload sigrund_requester; do has_module "$module"; done
  assert_module_absent sigrund_podman
  assert_absent sigrund-selinux-podman
  matchpathcon -n /usr/libexec/sigrund/sigrund | grep -q ':sigrund_daemon_exec_t:'
  install_packages "${podman_old[0]}"
  has_module sigrund_podman
  assert_absent selinux-policy-devel
  assert_absent podman
fi

# Existing operator-owned configuration and durable data survive upgrades/removal.
mkdir -p /var/lib/sigrund /var/log/sigrund
printf 'operator configuration\n' > /etc/sigrund/config.toml
printf 'identity and consumption sentinel\n' > /var/lib/sigrund/package-test
printf 'audit history sentinel\n' > /var/log/sigrund/package-test
sha256sum /etc/sigrund/config.toml /var/lib/sigrund/package-test /var/log/sigrund/package-test > /tmp/preserved.sha256
if [[ "$scenario" == selinux ]]; then
  install_packages "${daemon_new[0]}" "${policy_new[0]}" "${podman_new[0]}"
  for module in sigrund_daemon sigrund_workload sigrund_requester sigrund_podman; do has_module "$module"; done
else
  install_packages "${daemon_new[0]}"
  if [[ "$kind" == rpm ]]; then
    assert_absent sigrund-selinux
    assert_absent sigrund-selinux-podman
  fi
fi
if [[ "$scenario" != combined ]]; then
  assert_absent sigrun
  test ! -e /usr/bin/sigrun
fi
sha256sum --check /tmp/preserved.sha256
sigrund-approve-tui --help | grep -F 'Usage: sigrund-approve-tui '
test ! -e /etc/systemd/system/multi-user.target.wants/sigrund.service
executables=(/usr/bin/sigrund-anchor /usr/bin/sigrundctl /usr/bin/sigrund-approve /usr/bin/sigrund-approve-tui /usr/libexec/sigrund/sigrund)
if [[ "$scenario" == combined ]]; then
  executables+=(/usr/bin/sigrun)
fi
for executable in "${executables[@]}"; do
  test "$(stat -c '%u:%g:%a' "$executable")" = 0:0:755
done
if [[ "$scenario" == selinux ]]; then
  remove_packages sigrund-selinux-podman
  assert_module_absent sigrund_podman
  has_module sigrund_daemon
  remove_packages sigrund-selinux
  for module in sigrund_daemon sigrund_workload sigrund_requester; do assert_module_absent "$module"; done
  if matchpathcon -n /usr/libexec/sigrund/sigrund | grep -q ':sigrund_daemon_exec_t:'; then
    echo 'Removed policy left a stale daemon entrypoint context' >&2
    exit 1
  fi
  assert_absent selinux-policy-devel
  assert_absent podman
fi
remove_packages sigrund
sha256sum --check /tmp/preserved.sha256
assert_absent sigrund
test ! -e /usr/libexec/sigrund/sigrund
if [[ "$scenario" == combined ]]; then
  sigrun --help
  remove_packages sigrun
fi
assert_absent sigrun
test ! -e /usr/bin/sigrun
echo "Package install, upgrade, independence and removal checks passed ($scenario)."
