#/bin/bash

# Simple script, which contains 'recipes' for compilation of supported
# libraries.
# This script is called before the testing itself if a 'configuration' file,
# with library name, repository and branch, is present. If so, the desired
# library is compiled and 'installed' (by replacing an existing installation).
# The main disadvantage is that the compilation is perfomed in EACH job, which
# is time consuming and unnecessary. Possible future solution could be an
# external system, which would create RPMs for each supported OS and these
# RPMs could be then simply downloaded and installed by a package manager.

# TODO: following recipes contain a simple, working way of compiling each
# library and could be definitely improved.

# Arguments:
# $1: Library name (gnutls, nss or openssl)
# $2: Library repo address (git for gnutls and openssl, mercurial for nss)
# $3: Repository branch/tag name

if [[ $# -ne 3 ]]; then
    echo >&2 "$0: Invalid arguments"
    exit 1
fi

LIB_NAME="$1"
LIB_REPO="$2"
LIB_BRANCH="$3"

set -e

if [[ $LIB_NAME == "nss" ]]; then
    export USE_64=1

    # Install dependencies
    # Compiled library must be installed here, so it won't be overwritten later
    # when installed in some test-dependency chain
    REQS="nss mercurial zlib-devel gcc gcc-c++"
    $PKG_MAN -y install $REQS
    rpm -q $REQS

    if [ $USE_64 -eq 1 ]; then
        LIB_DIR="/usr/lib64"
    else
        LIB_DIR="/usr/lib"
    fi

    if [ ! -d nss ]; then
        hg clone "$LIB_REPO" nss
    fi

    if [ ! -d nspr ]; then
        hg clone https://hg.mozilla.org/projects/nspr nspr
    fi

    rm -fr dist
    cd nss
    hg update "$LIB_BRANCH"
    make nss_clean_all
    make nss_build_all &> build.log
    head -n 100 build.log
    cd ..
    # There must be a better way
    cd dist/*.OBJ
    cp -Hfrv --remove-destination lib/* ${LIB_DIR}/
    cp -Hfrv --remove-destination include/* /usr/include/
    cp -Hfrv --remove-destination bin/* ${LIB_DIR}/nss/unsupported-tools/
    cd ../..

    if [ ! -f version ]; then
        echo "
    #include <stdio.h>
    #include <dlfcn.h>

    int main() {
            void* lib = dlopen(\"${LIB_DIR}/libnss3.so\", RTLD_NOW);
            const char* (*func)() = dlsym(lib, \"NSS_GetVersion\");
            printf(\"%s\n\", func());

            dlclose(lib);
            return 0;
    }
    " > version.c
        gcc -o version version.c -ldl
        chmod +x version
    fi

    ./version
elif [[ $LIB_NAME == "openssl" ]]; then
    # Install dependencies
    # Compiled library must be installed here, so it won't be overwritten later
    # when installed in some test-dependency chain
    REQS="openssl zlib-devel git gcc lksctp-tools-devel"
    $PKG_MAN -y install $REQS
    rpm -q $REQS

    git clone "$LIB_REPO" openssl
    cd openssl
    git checkout "$LIB_BRANCH"
    # TODO: custom config options like no-ssl2, etc. (?)
    FLAGS="enable-ec_nistp_64_gcc_128 zlib sctp enable-camellia enable-seed"
    FLAGS+=" enable-rfc3779 enable-cms enable-md2 enable-rc5"
    FLAGS+=" no-mdc2 no-ec2m no-gost no-srp shared"
    ./config --prefix=/usr --openssldir=/etc/pki/tls $FLAGS
    echo "Compiling..."
    make depend &> build.log
    make all &>> build.log
    head -n 100 build.log
    # TODO: Is this necessary? (these tests take some time)
    # Requires: perl-Test-Harness perl-Test-Simple
    #make test
    echo "Installing..."
    make install &> build.log
    head -n 100 build.log
    openssl version
    cd ..
elif [[ $LIB_NAME == "gnutls" ]]; then
    # Install dependencies
    # Compiled library must be installed here, so it won't be overwritten later
    # when installed in some test-dependency chain
    REQS="gnutls zlib-devel git gcc p11-kit-devel gettext readline-devel"
    REQS+=" libtool automake autoconf texinfo nettle-devel autogen gettext-devel"
    REQS+=" libtasn1 libtasn1-devel gtk-doc libunistring-devel gperf bison"
    $PKG_MAN -y install $REQS
    # Workaround for RHEL 6 which does not have autogen it its repositories
    if ! rpm -q autogen; then
        $PKG_MAN -y --enablerepo epel-testing install autogen
    fi

    rpm -q $REQS

    git clone "$LIB_REPO" gnutls
    cd gnutls
    git checkout "$LIB_BRANCH"
    git submodule update --init
    make bootstrap &> build.log
    # TODO: RHEL/Fedora spec files use several switches, which (probably)
    # should be used here as well
    echo "Configuring..."
    ./configure --prefix=/usr --disable-non-suiteb-curves --disable-doc &>> build.log
    head -n 100 build.log
    echo "Compiling..."
    make &> build.log
    head -n 100 build.log
    # TODO: dist-hook is (probably) necessary to make gnutls-* --version
    # show correct version instead of @VERSION@ placeholder, which (probably)
    # needs a working dane support
    echo "Installing..."
    make install &> build.log
    head -n 100 build.log
    # FIXME: wrong version number because of the previous TODO
    gnutls-cli --version
    cd ..
else
    echo >&2 "$0: Invalid library name ($LIB_NAME)"
    exit 1
fi

exit 0
