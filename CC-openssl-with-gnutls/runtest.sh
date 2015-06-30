#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/openssl/Interoperability/CC-openssl-with-gnutls
#   Description: Test CC relevant ciphers with openssl and gnutls
#   Author: Hubert Kario <hkario@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2015 Red Hat, Inc.
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
. /usr/bin/rhts-environment.sh || exit 1
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="openssl"
PACKAGES="nss gnutls"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "rlImport openssl/certgen"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "cp gnutls-client.expect openssl-client.expect openssl-server.expect $TmpDir"
        rlRun "pushd $TmpDir"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen rsa-ca"
        rlRun "x509KeyGen -t dsa dsa-ca"
        rlRun "x509KeyGen -t ecdsa ecdsa-ca"
        rlRun "x509KeyGen rsa-server"
        rlRun "x509KeyGen -t dsa dsa-server"
        rlRun "x509KeyGen -t ecdsa ecdsa-server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=RSA CA' rsa-ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=DSA CA' dsa-ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=ECDSA CA' ecdsa-ca"
        rlRun "x509CertSign --CA rsa-ca rsa-server"
        rlRun "x509CertSign --CA dsa-ca dsa-server"
        rlRun "x509CertSign --CA ecdsa-ca ecdsa-server"
        rlRun "x509DumpCert ca" 0 "Root CA"
        rlRun "x509DumpCert rsa-ca" 0 "Intermediate RSA CA"
        rlRun "x509DumpCert dsa-ca" 0 "Intermediate DSA CA"
        rlRun "x509DumpCert ecdsa-ca" 0 "Intermediate ECDSA CA"
        rlRun "x509DumpCert rsa-server" 0 "Server RSA certificate"
        rlRun "x509DumpCert dsa-server" 0 "Server DSA certificate"
        rlRun "x509DumpCert ecdsa-server" 0 "Server ECDSA certificate"
        rlLogInfo "Loading configuration..."

        i=0
        # IETF names for ciphers
        declare -a C_NAME
        # OpenSSL names for ciphers
        declare -a C_OPENSSL
        # hex ID of ciphersuite (NSS ID)
        declare -a C_ID
        # intermediate CA used
        declare -a C_SUBCA
        # EE certificate used
        declare -a C_CERT
        # EE key used
        declare -a C_KEY

        #########################################
        #              CAUTION!                 #
        #########################################
        # This test is part of Common Criteria  #
        # interoperability testing, if you      #
        # modify cipher settings below          #
        # you have to modify it in all three    #
        # tests:                                #
        # OpenSSL with GnuTLS                   #
        # OpenSSL with NSS                      #
        # NSS with GnuTLS                       #
        #########################################

        #
        # RSA key exchange ciphers
        #

        C_NAME[$i]="TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        C_OPENSSL[$i]="DES-CBC3-SHA"
        C_ID[$i]="000A"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="AES128-SHA"
        C_ID[$i]="002F"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="AES256-SHA"
        C_ID[$i]="0035"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="AES128-SHA256"
        C_ID[$i]="003C"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="AES256-SHA256"
        C_ID[$i]="003D"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="AES128-GCM-SHA256"
        C_ID[$i]="009C"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_256_GCM_SHA384"
        C_OPENSSL[$i]="AES256-GCM-SHA384"
        C_ID[$i]="009D"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        #
        # FFDHE+RSA
        #

        C_NAME[$i]="TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
        C_OPENSSL[$i]="EDH-RSA-DES-CBC3-SHA"
        C_ID[$i]="0016"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="DHE-RSA-AES128-SHA"
        C_ID[$i]="0033"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="DHE-RSA-AES256-SHA"
        C_ID[$i]="0039"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="DHE-RSA-AES128-SHA256"
        C_ID[$i]="0067"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="DHE-RSA-AES256-SHA256"
        C_ID[$i]="006B"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="DHE-RSA-AES128-GCM-SHA256"
        C_ID[$i]="009E"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
        C_OPENSSL[$i]="DHE-RSA-AES256-GCM-SHA384"
        C_ID[$i]="009F"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        #
        # FFDHE+DSS
        #

        C_NAME[$i]="TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
        C_OPENSSL[$i]="EDH-DSS-DES-CBC3-SHA"
        C_ID[$i]="0013"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="DHE-DSS-AES128-SHA"
        C_ID[$i]="0032"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="DHE-DSS-AES256-SHA"
        C_ID[$i]="0038"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="DHE-DSS-AES128-SHA256"
        C_ID[$i]="0040"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="DHE-DSS-AES256-SHA256"
        C_ID[$i]="006A"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="DHE-DSS-AES128-GCM-SHA256"
        C_ID[$i]="00A2"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
        C_OPENSSL[$i]="DHE-DSS-AES256-GCM-SHA384"
        C_ID[$i]="00A3"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        i=$(($i+1))

        #
        # ECDHE+RSA
        #

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
        C_OPENSSL[$i]="ECDHE-RSA-DES-CBC3-SHA"
        C_ID[$i]="C012"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="ECDHE-RSA-AES128-SHA"
        C_ID[$i]="C013"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="ECDHE-RSA-AES256-SHA"
        C_ID[$i]="C014"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="ECDHE-RSA-AES128-SHA256"
        C_ID[$i]="C027"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
        C_OPENSSL[$i]="ECDHE-RSA-AES256-SHA384"
        C_ID[$i]="C028"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="ECDHE-RSA-AES128-GCM-SHA256"
        C_ID[$i]="C02F"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        C_OPENSSL[$i]="ECDHE-RSA-AES256-GCM-SHA384"
        C_ID[$i]="C030"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        i=$(($i+1))

        #
        # ECDHE+ECDSA
        #

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
        C_OPENSSL[$i]="ECDHE-ECDSA-DES-CBC3-SHA"
        C_ID[$i]="C008"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES128-SHA"
        C_ID[$i]="C009"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES256-SHA"
        C_ID[$i]="C00A"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES128-SHA256"
        C_ID[$i]="C023"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES256-SHA384"
        C_ID[$i]="C024"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES128-GCM-SHA256"
        C_ID[$i]="C02B"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES256-GCM-SHA384"
        C_ID[$i]="C02C"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        i=$(($i+1))

        rlLogInfo "Configuration loaded"
    rlPhaseEnd

    for j in ${!C_NAME[@]}; do
        rlPhaseStartTest "OpenSSL server GnuTLS client ${C_NAME[$j]} cipher"
            options=(openssl s_server)
            options+=(-key ${C_KEY[$j]} -cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            rlRun "expect openssl-server.expect ${options[*]} \
                   >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"

            options=(gnutls-cli)
            options+=(--x509cafile $(x509Cert ca))
            options+=(-p 4433 localhost)
            rlRun -s "expect gnutls-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlAssertGrep "server hello" $rlRun_LOG
            rlRun "kill $openssl_pid"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd

        rlPhaseStartTest "GnuTLS server OpenSSL client ${C_NAME[$j]} cipher"
            rlRun "gnutls-serv --echo -p 4433 --x509keyfile ${C_KEY[$j]} \
                   --x509certfile <(cat ${C_CERT[$j]} ${C_SUBCA[$j]}) \
                   >server.log 2>server.err &"
            gnutls_pid=$!
            rlRun "rlWaitForSocket 4433 -p $gnutls_pid"

            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-connect localhost:4433)
            rlRun -s "expect openssl-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlRun "[[ $(grep 'client hello' $rlRun_LOG | wc -l) -eq 2 ]]" 0 \
                "Check if server echo'ed back our message"
            rlRun "kill $gnutls_pid"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd
    done

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
