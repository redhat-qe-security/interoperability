#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/TLSv1-2-with-OpenSSL
#   Description: Verify interoperability of GnuTLS TLSv1.2 with OpenSSL
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
. /usr/bin/rhts-environment.sh || exit 1
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="gnutls"
PACKAGES="openssl gnutls"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "rlImport openssl/certgen"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "cp gnutls-client.expect openssl-client.expect openssl-server.expect $TmpDir"
        rlRun "pushd $TmpDir"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen rsa-ca"
        # --conservative is as a workaround for RHBZ# 1238279 & 1238290
        rlRun "x509KeyGen -t dsa --conservative -s 1024 1024dsa-ca"
        rlRun "x509KeyGen rsa-server"
        rlRun "x509KeyGen -t dsa --conservative -s 1024 1024dsa-server"
        rlRun "x509KeyGen rsa-client"
        rlRun "x509KeyGen -t dsa --conservative -s 1024 1024dsa-client"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=RSA CA' rsa-ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=1024DSA CA' 1024dsa-ca"
        rlRun "x509CertSign --CA rsa-ca rsa-server"
        rlRun "x509CertSign --CA 1024dsa-ca --md sha1 1024dsa-server"
        rlRun "x509CertSign --CA rsa-ca -t webclient rsa-client"
        rlRun "x509CertSign --CA 1024dsa-ca -t webclient --md sha1 1024dsa-client"
        rlRun "x509DumpCert ca" 0 "Root CA"
        rlRun "x509DumpCert rsa-ca" 0 "Intermediate RSA CA"
        rlRun "x509DumpCert 1024dsa-ca" 0 "Intermediate 1024DSA CA"
        rlRun "x509DumpCert rsa-server" 0 "Server RSA certificate"
        rlRun "x509DumpCert 1024dsa-server" 0 "Server 1024DSA certificate"
        rlRun "x509DumpCert rsa-client" 0 "Client RSA certificate"
        rlRun "x509DumpCert 1024dsa-client" 0 "Client 1024DSA certificate"
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

        #
        # RSA key exchange ciphers
        #

        C_NAME[$i]="TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        C_OPENSSL[$i]="DES-CBC3-SHA"
        C_ID[$i]="000A"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="AES128-SHA"
        C_ID[$i]="002F"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="AES256-SHA"
        C_ID[$i]="0035"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="AES128-SHA256"
        C_ID[$i]="003C"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="AES256-SHA256"
        C_ID[$i]="003D"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        #
        # FFDHE+RSA
        #

        C_NAME[$i]="TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
        C_OPENSSL[$i]="EDH-RSA-DES-CBC3-SHA"
        C_ID[$i]="0016"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="DHE-RSA-AES128-SHA"
        C_ID[$i]="0033"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="DHE-RSA-AES256-SHA"
        C_ID[$i]="0039"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="DHE-RSA-AES128-SHA256"
        C_ID[$i]="0067"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="DHE-RSA-AES256-SHA256"
        C_ID[$i]="006B"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        #
        # FFDHE+DSS
        #

        # since 2048bit DSA is undefined for TLS1.1, use 1024bit DSA
        # for cipher suites which can be used in TLS1.1, RHBZ#1238333
        C_NAME[$i]="TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
        C_OPENSSL[$i]="EDH-DSS-DES-CBC3-SHA"
        C_ID[$i]="0013"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
        C_CERT[$i]="$(x509Cert 1024dsa-server)"
        C_KEY[$i]="$(x509Key 1024dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="DHE-DSS-AES128-SHA"
        C_ID[$i]="0032"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
        C_CERT[$i]="$(x509Cert 1024dsa-server)"
        C_KEY[$i]="$(x509Key 1024dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="DHE-DSS-AES256-SHA"
        C_ID[$i]="0038"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
        C_CERT[$i]="$(x509Cert 1024dsa-server)"
        C_KEY[$i]="$(x509Key 1024dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="DHE-DSS-AES128-SHA256"
        C_ID[$i]="0040"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
        C_CERT[$i]="$(x509Cert 1024dsa-server)"
        C_KEY[$i]="$(x509Key 1024dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="DHE-DSS-AES256-SHA256"
        C_ID[$i]="006A"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
        C_CERT[$i]="$(x509Cert 1024dsa-server)"
        C_KEY[$i]="$(x509Key 1024dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
        i=$(($i+1))

        rlLogInfo "Configuration loaded"
    rlPhaseEnd

    for j in ${!C_NAME[@]}; do
      for prot in tls1_2 tls1_1; do

        # skip ciphers that work only in TLS1.2 when testing TLS1.1
        if [[ $prot == tls1_1 ]] && [[ ${C_TLS1_2_ONLY[$j]} == "True" ]]; then
            continue
        fi

        rlPhaseStartTest "OpenSSL server GnuTLS client ${C_NAME[$j]} cipher $prot protocol"
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
            if [[ $prot == tls1_2 ]]; then
                options+=(--priority NORMAL:+VERS-TLS1.2)
            fi
            if [[ $prot == tls1_1 ]]; then
                options+=(--priority NORMAL:-VERS-TLS1.2)
            fi
            options+=(-p 4433 localhost)
            rlRun -s "expect gnutls-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlAssertGrep "server hello" $rlRun_LOG
            if [[ $prot == tls1_1 ]]; then
                rlAssertGrep "Version: TLS1.1" $rlRun_LOG
            else
                rlAssertGrep "Version: TLS1.2" $rlRun_LOG
            fi
            rlRun "kill $openssl_pid"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd

        rlPhaseStartTest "GnuTLS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol"
            options=(gnutls-serv --echo -p 4433)
            options+=(--priority NORMAL:+VERS-TLS1.2)
            options+=(--x509keyfile ${C_KEY[$j]})
            options+=(--x509certfile "<(cat ${C_CERT[$j]} ${C_SUBCA[$j]})")
            options+=(">server.log" "2>server.err" "&")
            rlRun "${options[*]}"
            gnutls_pid=$!
            rlRun "rlWaitForSocket 4433 -p $gnutls_pid"

            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-connect localhost:4433)
            if [[ $prot == tls1_1 ]]; then
                options+=(-no_tls1_2)
            fi
            rlRun -s "expect openssl-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlRun "[[ $(grep 'client hello' $rlRun_LOG | wc -l) -eq 2 ]]" 0 \
                "Check if server echo'ed back our message"
            if [[ $prot == tls1_1 ]]; then
                rlAssertGrep "Protocol  : TLSv1.1" $rlRun_LOG
            else
                rlAssertGrep "Protocol  : TLSv1.2" $rlRun_LOG
            fi
            rlRun "kill $gnutls_pid"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd

        rlPhaseStartTest "OpenSSL server GnuTLS client ${C_NAME[$j]} cipher $prot protocol client cert"
            options=(openssl s_server)
            options+=(-key ${C_KEY[$j]} -cert ${C_CERT[$j]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-Verify 1)
            rlRun "expect openssl-server.expect ${options[*]} \
                   >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"

            options=(gnutls-cli)
            options+=(--x509cafile $(x509Cert ca))
            options+=(--x509keyfile ${C_CLNT_KEY[$j]})
            options+=(--x509certfile ${C_CLNT_CERT[$j]})
            if [[ $prot == tls1_2 ]]; then
                options+=(--priority NORMAL:+VERS-TLS1.2)
            fi
            if [[ $prot == tls1_1 ]]; then
                options+=(--priority NORMAL:-VERS-TLS1.2)
            fi
            options+=(-p 4433 localhost)
            rlRun -s "expect gnutls-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlAssertGrep "server hello" $rlRun_LOG
            if [[ $prot == tls1_1 ]]; then
                rlAssertGrep "Version: TLS1.1" $rlRun_LOG
            else
                rlAssertGrep "Version: TLS1.2" $rlRun_LOG
            fi
            rlRun "kill $openssl_pid"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd

        rlPhaseStartTest "GnuTLS server OpenSSL client ${C_NAME[$j]} cipher $prot protocol client cert"
            options=(gnutls-serv --echo -p 4433)
            options+=(--priority NORMAL:+VERS-TLS1.2)
            options+=(--x509keyfile ${C_KEY[$j]})
            options+=(--x509certfile "<(cat ${C_CERT[$j]} ${C_SUBCA[$j]})")
            options+=(--x509cafile "<(cat $(x509Cert ca) ${C_SUBCA[$j]})")
            if rlIsRHEL '6'; then
                options+=(--require-cert)
            else
                options+=(--require-client-cert --verify-client-cert)
            fi
            options+=(">server.log" "2>server.err" "&")
            rlRun "${options[*]}"
            gnutls_pid=$!
            rlRun "rlWaitForSocket 4433 -p $gnutls_pid"

            options=(openssl s_client)
            options+=(-CAfile $(x509Cert ca))
            options+=(-cipher ${C_OPENSSL[$j]})
            options+=(-key ${C_CLNT_KEY[$j]})
            options+=(-cert ${C_CLNT_CERT[$j]})
            options+=(-connect localhost:4433)
            if [[ $prot == tls1_1 ]]; then
                options+=(-no_tls1_2)
            fi
            rlRun -s "expect openssl-client.expect ${options[*]}"
            rlAssertGrep "client hello" $rlRun_LOG
            rlRun "[[ $(grep 'client hello' $rlRun_LOG | wc -l) -eq 2 ]]" 0 \
                "Check if server echo'ed back our message"
            if [[ $prot == tls1_1 ]]; then
                rlAssertGrep "Protocol  : TLSv1.1" $rlRun_LOG
            else
                rlAssertGrep "Protocol  : TLSv1.2" $rlRun_LOG
            fi
            rlRun "kill $gnutls_pid"
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd
      done
    done


    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
