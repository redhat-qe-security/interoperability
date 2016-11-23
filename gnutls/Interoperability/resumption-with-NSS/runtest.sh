#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/resumption-with-NSS
#   Description: Verify that session resumption between GnuTLS and NSS works
#   Author: Hubert Kario <hkario@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2016 Red Hat, Inc.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="gnutls"
PACKAGES="gnutls nss"

SERVER_UTIL="/usr/lib64/nss/unsupported-tools/selfserv"
CLIENT_UTIL="/usr/lib64/nss/unsupported-tools/strsclnt"
[ ! -x $SERVER_UTIL ] && SERVER_UTIL="/usr/lib/nss/unsupported-tools/selfserv"
[ ! -x $CLIENT_UTIL ] && CLIENT_UTIL="/usr/lib/nss/unsupported-tools/strsclnt"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "rlImport openssl/certgen"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "x509KeyGen rsa-ca"
        rlRun "x509KeyGen rsa-server"
        rlRun "x509SelfSign rsa-ca"
        rlRun "x509CertSign --CA rsa-ca --DN CN=localhost4 rsa-server"
        rlRun "mkdir ca-db" 0 "Directory with just CA certificate"
        rlRun "certutil -N --empty-password -d sql:./ca-db" 0 "Create database for CA cert"
        rlRun "certutil -A -d sql:./ca-db -n ca -t 'cC,,' -a -i $(x509Cert rsa-ca)"\
            0 "Import CA certificate"
    rlPhaseEnd

    rlPhaseStartTest "NSS server"
        rlRun "mkdir nssdb/"
        rlRun "certutil -N --empty-password -d sql:nssdb"
        rlRun "certutil -A -d sql:nssdb -n ca -t 'cC,,' -a -i $(x509Cert rsa-ca)"
        rlRun "pk12util -i $(x509Key --pkcs12 --with-cert rsa-server) -d sql:./nssdb -W ''"

        rlLogInfo "Test proper"
        rlRun "$SERVER_UTIL -d sql:nssdb -p 4433 -V tls1.0: -H 1 -n rsa-server >server.log 2>server.err &"
        nss_pid=$!
        rlRun "rlWaitForSocket -p $nss_pid 4433"
        for sett in "NORMAL" "NORMAL:+VERS-TLS1.2" "NORMAL:-VERS-TLS1.2"; do
            rlRun -s "sleep 2 | gnutls-cli --priority '$sett' --resume --x509cafile $(x509Cert rsa-ca) --port 4433 localhost4"
            rlAssertGrep "This is a resumed session" $rlRun_LOG
            rlAssertNotGrep "failure" $rlRun_LOG -i
        done
        rlRun "kill $nss_pid" 0,1
        rlRun "rlWait -s 9 $nss_pid" 143
    rlPhaseEnd

    rlPhaseStartTest "GnuTLS server"
        rlRun "gnutls-serv --priority NORMAL:+VERS-TLS1.2 --x509keyfile $(x509Key rsa-server) --x509certfile $(x509Cert rsa-server) --http --port 4433 >server.log 2>server.err &"
        gnutls_pid=$!
        rlRun "rlWaitForSocket -p $gnutls_pid 4433"
        for sett in "tls1.1" "tls1.2"; do
            rlRun -s "$CLIENT_UTIL -p 4433 -d sql:ca-db -c 100 -P 20 -V tls1.0:$sett localhost4" 1
            rlAssertGrep "80 cache hits" "$rlRun_LOG"
            rlAssertGrep "0 stateless resumes" $rlRun_LOG
        done
        rlRun "kill $gnutls_pid" 0,1
        rlRun "rlWait -s 9 $gnutls_pid" 143,1
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
rlGetTestState
