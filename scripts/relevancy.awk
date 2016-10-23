#!/bin/gawk -f

# Replace RHEL* releases with Centos
function release_subst(rel) {
    rel = tolower(rel);
    if(match(rel, "^rhel.*"))
        return "centos"

    return rel;
}

BEGIN {
    if(os_type == "" || os_ver == "") {
        print "Missing arguments";
        exit 1;
    }

    os_type = release_subst(os_type);
    os_ver = os_ver;
    print "Checking relevancy for " os_type " " os_ver;
}

# Match "Releases:" line from test's Makefile and split releases string
# into an array
match($0, /\"Releases:[[:space:]]*(.*)\"/, m) {
    split(m[1], items, /[[:space:]]+/);
}

END {
    for(i in items) {
        # Split each release to exclude sign (-), release name and release
        # version. If parsed release matches the release passed as arguments
        # and the exclude flags is set, return 1
        # If no release is matched (or matched release doesn't have the
        # exclude flags set), return 0
        if(match(items[i], /^([-])?([^0-9]+)([0-9]+)$/, release)) {
            exclude = (release[1] == "-") ? 1 : 0;
            rel_type = release_subst(release[2]);
            rel_ver = release[3];
            print rel_type " " rel_ver " " ((exclude) ? "exclude" : "ok")
            if(rel_type == os_type && rel_ver == os_ver && exclude)
                exit 1;
        }
    }

    exit 0;
}
