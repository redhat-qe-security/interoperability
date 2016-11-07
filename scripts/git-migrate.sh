#!/usr/bin/bash

function confirmation() {
    read -p "$1 (y/n)" -n 1 -r
    echo
    if ! [[ $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
}

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 commit commit commit ..."
    exit 1
fi

GIT_ROOT="$(basename $(git rev-parse --show-toplevel))"
if [[ "$GIT_ROOT" =~ (openssl|nss|gnutls) ]]; then
    GIT_TYPE="downstream"
else
    GIT_TYPE="upstream"
fi

echo -e "git root directory is '$GIT_ROOT' which is \e[1m$GIT_TYPE\e[0m"
confirmation "Is this information correct?"
if [[ "$GIT_TYPE" == "downstream" ]]; then
    echo "This directory will be used as a component name for a path substitution"
    confirmation "Is this setup OK?"
fi

echo "Requested patches for following commits:"
git show -s --oneline $@

echo "-------------------"

for commit in "$@"; do
    echo "Generating patch for $commit"
    patch="$(git format-patch -1 $commit)"
    if [[ $? -eq 0 && -n $patch ]]; then
        tmpfile="$(mktemp)"
        mv "$patch" "$tmpfile"
        awk -v dstr_comp="$GIT_ROOT" '
        function bold(text) {
            return "\033[1m" text "\033[0m";
        }
        function green(text) {
            return "\033[32m" text "\033[39m";
        }
        function red(text) {
            return "\033[31m" text "\033[39m";
        }

        # Match diff paths, eg.:
        # --- a/openssl/Interoperability/CC-openssl-with-gnutls/runtest.sh
        # +++ b/openssl/Interoperability/CC-openssl-with-gnutls/runtest.sh
        match($0, /^[+-]{3} [ab]\/([^\/]+)\/.+$/, m) {
            if(m[1] ~ /(openssl|nss|gnutls)/) {
                # First path component is a component name => upstream repo
                # Supported components: openssl, nss, gnutls
                print "Found an " bold("upstream") " path: " green($0) > "/dev/stderr"
                # Remove the component name from the path
                $0 = gensub(/^([+-]{3} [ab])\/[^\/]+(\/.+)$/,
                       "\\1\\2", 1, $0);
                print "Rewriting this path to: " red($0) > "/dev/stderr"
            } else if(m[1] ~ /(Interoperability)/) {
                # First path component is a test type => downstream repo
                # Supported test types: Interoperability
                print "Found a " bold("downstream") " path: " green($0) > "/dev/stderr"
                # Prepend the component name to the path
                $0 = gensub(/^([+-]{3} [ab]\/)([^\/]+\/.+)$/,
                       "\\1" dstr_comp "/\\2", 1, $0);
                print "Rewriting this path to:  " red($0)> "/dev/stderr"
            }
        }
        {
            print $0;
        }
        ' "$tmpfile" > "$patch"
        echo "Patch saved as $patch"
        rm "$tmpfile"
    else
        echo >&2 "git format-patch failed: ($patch)"
    fi
done
