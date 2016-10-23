#!/bin/bash

if [[ $# < 2 ]]; then
    echo >&2 "Missing arguments"
    exit 1
fi

OS_TYPE="$1"
OS_VERSION="$2"

yum -y makecache
# epel-release is not available on fedora
if [[ $OS_TYPE != "fedora" ]]; then
    yum -y install epel-release
fi

yum -y install openssl nss gnutls net-tools coreutils gawk \
               gnutls-utils expect make beakerlib findutils

EC=0

export PATH=${PATH}:/workspace/scripts

while read test; do
    echo "Running test: $test"
    pushd "$(dirname "$test")"
    # Check relevancy
    if ! relevancy.awk -v os_type=$OS_TYPE -v os_ver=$OS_VERSION Makefile; then
        echo "This test is not relevant for current release"
        continue
    fi
    # Works only for beakerlib tests
    make run
    if [[ $? -ne 0 ]]; then
        EC=1
    fi
    popd
done <<< "$(find /workspace -type f ! -path "*/Library/*" -name "runtest.sh")"

exit $EC
