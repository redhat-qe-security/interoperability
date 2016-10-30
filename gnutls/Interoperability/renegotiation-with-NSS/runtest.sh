#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/renegotiation-with-NSS
#   Description: Test renegotiating the connection with NSS
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

CLNT="/usr/lib64/nss/unsupported-tools/tstclnt"
[[ ! -x $CLNT ]] && CLNT="/usr/lib/nss/unsupported-tools/tstclnt"
SERV="/usr/lib64/nss/unsupported-tools/selfserv"
[[ ! -x $SERV ]] && SERV="/usr/lib/nss/unsupported-tools/selfserv"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "cp nss-client.expect $TmpDir"
        rlRun "pushd $TmpDir"
        rlRun "openssl req -x509 -newkey rsa -keyout localhost.key -out localhost.crt -nodes -batch -subj /CN=localhost4"
        rlRun "openssl pkcs12 -export -passout pass:  -out localhost.p12 -inkey localhost.key -in localhost.crt"
        rlRun "mkdir nssdb"
        rlRun "certutil -N -d sql:nssdb --empty-password"
        rlRun "pk12util -i localhost.p12 -d sql:nssdb -W ''"
        rlRun "certutil -A -d sql:nssdb -n localhost4 -t 'cC,,' -a -i localhost.crt"
        rlRun "certutil -L -d sql:nssdb"
    rlPhaseEnd

    rlPhaseStartTest "nss server"
        rlRun "$SERV -d sql:nssdb -n localhost4 -V ssl3: -p 4433 >server.log 2>server.err &"
        nss_pid=$!
        rlRun "rlWaitForSocket -p $nss_pid 4433"
        for sett in NORMAL "NORMAL:+VERS-TLS1.2" "NORMAL:-VERS-TLS1.2"; do
            rlRun -s "gnutls-cli --priority '$sett' --rehandshake --x509cafile localhost.crt --port 4433 localhost4 </dev/null"
            rlAssertGrep "ReHandshake was completed" $rlRun_LOG
            rlAssertNotGrep "failure" $rlRun_LOG -i
        done
        rlRun "kill $nss_pid" 0,1
        rlRun "rlWait $nss_pid" 143
        rlRun "cat server.log"
        rlRun "cat server.err"
    rlPhaseEnd

    rlPhaseStartTest "gnutls server"
        rlRun "gnutls-serv --priority NORMAL:+VERS-TLS1.2 --x509keyfile localhost.key --x509certfile localhost.crt --http --port 4433 >server.log 2>server.err &"
        gnutls_pid=$!
        rlRun "rlWaitForSocket -p $gnutls_pid 4433"
        for sett in "tls1.1" "tls1.2"; do
            rlRun -s "./nss-client.expect $CLNT -V ssl3:$sett -r 1 -d sql:nssdb -p 4433 -h localhost4"
            rlAssertGrep "HTTP/1.0 200 OK" $rlRun_LOG
            rlAssertGrep "$sett" $rlRun_LOG -i
        done
        rlRun "kill $gnutls_pid" 0,1
        rlRun "rlWait $gnutls_pid" 143,1
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
