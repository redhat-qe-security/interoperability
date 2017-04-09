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

# Compare test name with glob expression using extended glob patterns
# $1 - test name
# $2 - glob pattern
function test_name_relevancy() {
    # See: http://wiki.bash-hackers.org/syntax/pattern#extended_pattern_language
    # Save the original state
    shopt -q extglob
    local STATE=$?
    # Enable extglob
    shopt -s extglob
    [[ $1 == $2 ]]
    local RES=$?
    # If the extension was originally disabled, disable it
    if [[ $STATE -ne 0 ]]; then
        shopt -u extglob
    fi

    return $RES
}

# Compile a supported SSL/TLS library from sources
# If the 'library-repo' file exists in the root of the repository, this
# function parses it and compiles the SSL/TLS library according that
# configuration.
#
# Format of library-repo file:
# export DEV_LIBRARY_NAME="name" # where name could be gnutls, nss or openssl
# export DEV_LIBRARY_REPO="repo_address" # Repository address
# export DEV_LIBRARY_BRANCH="branch_name" # Repository branch
#
# Example:
# export DEV_LIBRARY_NAME="gnutls"
# export DEV_LIBRARY_REPO="https://gitlab.com/gnutls/gnutls.git"
# export DEV_LIBRARY_BRANCH="gnutls_3_5_11"
#
function compile_library() {
    local LIBRARY_FILE="/workspace/library-repo"
    local COMPILE_SCRIPT="/workspace/scripts/lib-compile.sh"

    if [[ ! -f $LIBRARY_FILE ]]; then
        echo "No 'library-repo' file found, continuing without compilation..."
        return 0
    fi

    source "${LIBRARY_FILE}"

    for var in REPO BRANCH NAME; do
        exp="DEV_LIBRARY_${var}"
        if [[ -z ${exp} ]]; then
            echo >&2 "Missing '${exp}'"
            return 1
        fi
    done

    chmod +x "$COMPILE_SCRIPT"
    $COMPILE_SCRIPT "$DEV_LIBRARY_NAME" "$DEV_LIBRARY_REPO" "$DEV_LIBRARY_BRANCH"
    EC=$?

    if [[ $EC -ne 0 ]]; then
        cat "${DEV_LIBRARY_NAME}/build.log"
    fi

    return $EC
}

set +x

if [[ $# < 3 ]]; then
    echo >&2 "Missing arguments"
    exit 1
fi

OS_TYPE="$1"
OS_VERSION="$2"
COMPONENT="$3"
TEST_GLOB="$4"

# As the $OS_VERSION is used for relevancy, we need to replace the 'latest'
# version tag with the actual OS version
# So far the 'latest' tag is used only for Fedora
if [[ $OS_VERSION == "latest" ]]; then
    OS_VERSION="$(awk '{ print $3; }' < /etc/fedora-release)"
    if ! [[ $OS_VERSION =~ ^[0-9]+$ ]]; then
        echo >&2 "FATAL: Couldn't determine OS version ($OS_VERSION)"
        exit 1
    fi
fi

if [[ $OS_TYPE == "fedora" ]]; then
    export PKG_MAN="dnf"
else
    export PKG_MAN="yum"
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
$PKG_MAN -y install net-tools coreutils gawk expect make beakerlib findutils \
                    procps-ng

if [[ $OS_TYPE == "fedora" ]]; then
    $PKG_MAN --enablerepo updates-testing -y install beakerlib
else
    $PKG_MAN --enablerepo epel-testing -y install beakerlib
fi

# WORKAROUND: Replace all rlIsRHEL calls with rlIsCentos
if [[ $OS_TYPE == "centos" ]]; then
    echo 'rlIsRHEL() { rlIsCentOS "$@"; }' >> /usr/share/beakerlib/testing.sh
fi

# Library compilation
if ! compile_library; then
    echo >&2 "Library compilation failed"
    exit 1
fi

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

    # Check if glob pattern is set
    if [[ ! -z "$TEST_GLOB" ]]; then
        # If so, check if it matches current test name
        TEST_NAME="$(basename $(dirname "$test"))"
        if ! test_name_relevancy "$TEST_NAME" "$TEST_GLOB"; then
            echo "Test '$TEST_NAME' excluded by given glob expression: $TEST_GLOB"
            SKIPPED+=("$test")
            continue
        fi
    fi

    # Makefile is necessary for test execution
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
