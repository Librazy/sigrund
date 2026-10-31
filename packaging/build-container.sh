#!/bin/bash
# Runs only in the disposable target-distribution CI build container.
set -euo pipefail
kind=$1
case "$kind" in
  deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends build-essential dpkg-dev binutils curl ca-certificates python3
    ;;
  rpm)
    dnf install -y gcc gcc-c++ glibc-devel rpm-build redhat-rpm-config binutils \
      tar gzip findutils curl-minimal ca-certificates python3
    ;;
  *) exit 64 ;;
esac

mkdir /build
tar -C /src --exclude=.git --exclude=target --exclude=__pycache__ -cf - . | tar -C /build -xf -
cd /build
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  https://sh.rustup.rs -o /tmp/rustup-init.sh
sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain none --no-modify-path
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release --locked -p sigrund \
  --bin sigrun --bin sigrund --bin sigrundctl --bin sigrund-approve

# Two revisions of the same build exercise a real package-manager upgrade.
python3 packaging/build.py --format "$kind" --release "$PACKAGE_REVISION.0" --output /out/previous
python3 packaging/build.py --format "$kind" --release "$PACKAGE_REVISION.1" --output /out/packages
rustc --version > /out/packages/build-info.txt
cargo --version >> /out/packages/build-info.txt
cat /etc/os-release >> /out/packages/build-info.txt
printf 'source=%s\nsource_date_epoch=%s\n' "$SOURCE_COMMIT" "$SOURCE_DATE_EPOCH" >> /out/packages/build-info.txt
