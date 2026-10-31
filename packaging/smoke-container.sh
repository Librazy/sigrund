#!/bin/bash
# Runs in a fresh disposable target container, not the build container or host.
set -euo pipefail
kind=$1
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
  client_old=(/out/previous/sigrun-*.rpm)
  client_new=(/out/packages/sigrun-*.rpm)
  daemon_old=(/out/previous/sigrund-*.rpm)
  daemon_new=(/out/packages/sigrund-*.rpm)
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
install_packages "${client_old[0]}"
sigrun --help
assert_absent sigrund
test ! -e /usr/libexec/sigrund/sigrund
test ! -e /usr/lib/systemd/system/sigrund.service
install_packages "${client_new[0]}"
sigrun --help

install_packages "${daemon_old[0]}"
/usr/libexec/sigrund/sigrund --help
sigrund-approve --help
sigrundctl --validate-uuid "$(sigrundctl uuidv7)"
systemd-analyze verify /usr/lib/systemd/system/sigrund.service
test ! -e /etc/sigrund/config.toml
test ! -e /var/lib/sigrund/host_id
test ! -e /etc/systemd/system/multi-user.target.wants/sigrund.service

# Existing operator-owned configuration and durable data survive upgrades/removal.
mkdir -p /var/lib/sigrund /var/log/sigrund
printf 'operator configuration\n' > /etc/sigrund/config.toml
printf 'identity and consumption sentinel\n' > /var/lib/sigrund/package-test
printf 'audit history sentinel\n' > /var/log/sigrund/package-test
sha256sum /etc/sigrund/config.toml /var/lib/sigrund/package-test /var/log/sigrund/package-test > /tmp/preserved.sha256
install_packages "${daemon_new[0]}"
sha256sum --check /tmp/preserved.sha256
test ! -e /etc/systemd/system/multi-user.target.wants/sigrund.service
for executable in /usr/bin/sigrun /usr/bin/sigrundctl /usr/bin/sigrund-approve /usr/libexec/sigrund/sigrund; do
  test "$(stat -c '%u:%g:%a' "$executable")" = 0:0:755
done
remove_packages sigrund
sha256sum --check /tmp/preserved.sha256
assert_absent sigrund
test ! -e /usr/libexec/sigrund/sigrund
sigrun --help
remove_packages sigrun
assert_absent sigrun
test ! -e /usr/bin/sigrun
echo 'Package install, upgrade, independence and removal checks passed.'
