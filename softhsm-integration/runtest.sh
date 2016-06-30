#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/softhsm-integration
#   Description: Integration with softhsm PKCS#11 module.
#   Author: Stanislav Zidek <szidek@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2016 Red Hat, Inc.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 2 of
#   the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE.  See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see http://www.gnu.org/licenses/.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/bin/rhts-environment.sh || exit 1
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="gnutls"

SH_CONF="softhsm.conf"
SH_PROVIDER="/usr/lib64/pkcs11/libsofthsm2.so"
SH_PIN=1234

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

    rlPhaseStartTest
        cat >$SH_CONF <<_EOF
directories.tokendir = ./db
objectstore.backend = file
_EOF
        rlRun "mkdir db"
        rlRun "export SOFTHSM2_CONF=./$SH_CONF"
        rlRun "softhsm2-util --init-token --slot 0 --label test --so-pin $SH_PIN --pin $SH_PIN" 0 \
            "Initialize token"
        options=(
                "--batch" "--login"
                "--outfile publickey"
                "--generate-rsa" "--label rsa"
                "--provider $SH_PROVIDER"
                )
        rlRun "GNUTLS_PIN=$SH_PIN p11tool ${options[*]}" 0 "Generate key and cert"
        options=(
                "--batch" "--list-all"
                "--provider $SH_PROVIDER"
                )
        rlRun -s "GNUTLS_PIN=$SH_PIN p11tool --login ${options[*]}" 0 "List all objects"
        rlAssertEquals "Expected two objects in total (private & public key)" \
            $(grep -c "^Object" $rlRun_LOG) 2
        rlAssertGrep "Type: Private key" $rlRun_LOG
        rlAssertGrep "Type: Public key" $rlRun_LOG
        rm -f $rlRun_LOG
        rlRun -s "p11tool ${options[*]}" 0 "List public objects"
        rlAssertEquals "Expected just one non-private object (public key)" \
            $(grep -c "^Object" $rlRun_LOG) 1
        rlAssertGrep "Type: Public key" $rlRun_LOG
        rm -f $rlRun_LOG
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
