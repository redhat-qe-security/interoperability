#!/bin/bash

function fold_start() {
    if [[ -z $1 ]]; then
        echo >&2 "Fold: missing argument"
    fi
    echo -en "travis_fold:start:$1\\r"
}

function fold_end() {
    if [[ -z $1 ]]; then
        echo >&2 "Fold: missing argument"
    fi
    echo -en "travis_fold:end:$1\\r"
}

function keep_alive() {
    while true; do
        echo "[KEEPALIVE] $(date)"
        sleep 300
    done
}

set +x

if [[ $# < 3 ]]; then
    echo >&2 "Missing arguments"
    exit 1
fi

OS_TYPE="$1"
OS_VERSION="$2"
COMPONENT="$3"
if [[ $OS_TYPE == "fedora" ]]; then
    PKG_MAN="dnf"
else
    PKG_MAN="yum"
fi

fold_start "machine-setup"
$PKG_MAN -y makecache
# Do a full system upgrade
$PKG_MAN -y upgrade

# epel-release is not available on fedora
if [[ $OS_TYPE != "fedora" ]]; then
    $PKG_MAN -y install epel-release
fi

# Install necessary packages/dependencies
$PKG_MAN -y install net-tools coreutils gawk expect make beakerlib findutils

EC=0
SKIP=0
INDEX=0
EXECUTED=()
FAILED=()
SKIPPED=()

export PATH=${PATH}:/workspace/scripts

fold_end "machine-setup"
keep_alive &

# Just beautiful
for test in $(find /workspace -type f ! -path "*/Library/*" \
                              -path "*/$COMPONENT/*" -name "runtest.sh");
do
    ((INDEX++))
    fold_start "runtest.sh.$INDEX"
    SKIP=0

    echo "Running test: $test"
    pushd "$(dirname "$test")"
    if [[ ! -f Makefile ]]; then
        echo >&2 "Missing Makefile"
        EC=1
        SKIP=1
    fi
    if [[ $SKIP -eq 0 ]]; then
        # Check relevancy
        if relevancy.awk -v os_type=$OS_TYPE -v os_ver=$OS_VERSION Makefile; then
            # Install test dependencies
            DEPS="$(awk '
                match($0, /\"Requires:[[:space:]]*(.*)\"/, m) {
                    print m[1];
                }' Makefile)"
            if [[ ! -z $DEPS ]]; then
                $PKG_MAN -y install $DEPS
            fi
            # Works only for beakerlib tests
            make run
            if [[ $? -ne 0 ]]; then
                FAILED+=("$test")
                EC=1
            fi
        else
            echo "This test is not relevant for current release"
            SKIP=1
        fi
    fi
    popd

    if [[ $SKIP -eq 0 ]]; then
        EXECUTED+=("$test")
    else
        SKIPPED+=("$test")
    fi

    fold_end "runtest.sh.$INDEX"
done

echo "RESULTS:"

echo "Executed tests:"
printf '%s\n' "${EXECUTED[@]}"

echo "Skipped tests:"
printf '%s\n' "${SKIPPED[@]}"

echo "Failed tests:"
printf '%s\n' "${FAILED[@]}"

exit $EC
