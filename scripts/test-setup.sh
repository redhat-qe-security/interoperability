#!/bin/bash -x

if [[ $# < 3 ]]; then
    echo >&2 "Missing arguments"
    exit 1
fi

OS_TYPE="$1"
OS_VERSION="$2"
COMPONENT="$3"
CONT_NAME="${OS_TYPE}-${OS_VERSION}-${COMPONENT}"
CERTGEN_REPO="https://github.com/redhat-qe-security/certgen"
CERTGEN_PATH="openssl/Library/certgen"

# Prepare necessary libraries
# openssl/certgen:
TMP_DIR="$(mktemp -d tmp.XXXXX)"
mkdir -p "$CERTGEN_PATH"
git clone "$CERTGEN_REPO" "$TMP_DIR"
cp -a "$TMP_DIR/certgen/." "$CERTGEN_PATH/"
rm -fr "$TMP_DIR"
# fake distribution/fips (at least for now)
LIB_PATH="distribution/Library/fips"
mkdir -p "$LIB_PATH"
echo "# library-prefix = fips" > "$LIB_PATH/lib.sh"
echo "fipsLibraryLoaded() { return 0; }" >> "$LIB_PATH/lib.sh"

sudo docker run --rm --name "$CONT_NAME" \
                -v $PWD:/workspace:rw \
                ${OS_TYPE}:${OS_VERSION} \
                /bin/bash -c \
                "bash -x /workspace/scripts/test-runner.sh $OS_TYPE $OS_VERSION"
