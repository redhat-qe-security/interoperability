#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/resumption-with-OpenSSL
#   Description: What the test does
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
PACKAGES="gnutls openssl"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "openssl req -x509 -newkey rsa -keyout localhost.key -out localhost.crt -nodes -batch -subj /CN=localhost"
    rlPhaseEnd

    rlPhaseStartTest "openssl server"
        rlRun "openssl s_server -www -key localhost.key -cert localhost.crt >server.log 2>server.err &"
        openssl_pid=$!
        rlRun "rlWaitForSocket -p $openssl_pid 4433"
        for sett in NORMAL "NORMAL:+VERS-TLS1.2" "NORMAL:-VERS-TLS1.2"; do
            rlRun -s "gnutls-cli --priority '$sett' --resume --x509cafile localhost.crt --port 4433 localhost </dev/null"
            rlAssertGrep "This is a resumed session" $rlRun_LOG
            rlAssertNotGrep "failure" $rlRun_LOG -i
        done
        rlRun "kill $openssl_pid"
        rlRun "rlWait -s 9 $openssl_pid" 143
    rlPhaseEnd

    rlPhaseStartTest "gnutls server"
        rlRun "gnutls-serv --priority NORMAL:+VERS-TLS1.2 --x509keyfile localhost.key --x509certfile localhost.crt --http --port 4433 >server.log 2>server.err &"
        gnutls_pid=$!
        rlRun "rlWaitForSocket -p $gnutls_pid 4433"
        for sett in "" "-tls1_1" "-tls1_2"; do
            rlRun -s "openssl s_client -connect localhost:4433 -no_ticket -CAfile localhost.crt $sett -sess_out sess.pem </dev/null"
            rlAssertGrep "New, TLSv1/SSLv3" $rlRun_LOG
            rlAssertNotGrep "Reused, TLSv1/SSLv3" $rlRun_LOG
            rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
            rlRun -s "openssl s_client -connect localhost:4433 -no_ticket -CAfile localhost.crt $sett -sess_in sess.pem </dev/null"
            rlAssertGrep "Reused, TLSv1/SSLv3" $rlRun_LOG
            rlAssertNotGrep "New, TLSv1/SSLv3" $rlRun_LOG
            rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
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
