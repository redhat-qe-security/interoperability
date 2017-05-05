#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/signature_algorithms-with-OpenSSL
#   Description: Test if the signature_algorithms extension works with OpenSSL
#   Author: Frantisek Sumsal <fsumsal@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc.
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
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="gnutls"
PACKAGES="gnutls openssl"
GNUTLS_PROFILE="NORMAL:-VERS-ALL:+VERS-TLS1.2:-SIGN-ALL:+DHE-DSS"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        rlAssertRpm --all
        rlRun "rlImport openssl/certgen"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen rsa-ca"
        rlRun "x509KeyGen -t dsa dsa-ca"
        rlRun "x509KeyGen -t ecdsa ecdsa-ca"
        rlRun "x509KeyGen rsa-server"
        rlRun "x509KeyGen -t dsa dsa-server"
        rlRun "x509KeyGen -t dsa -s 1024 dsa-server-1024"
        rlRun "x509KeyGen -t ecdsa ecdsa-server"
        rlRun "x509KeyGen rsa-client"
        rlRun "x509KeyGen -t dsa dsa-client"
        rlRun "x509KeyGen -t dsa -s 1024 dsa-client-1024"
        rlRun "x509KeyGen -t ecdsa ecdsa-client"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=RSA CA' rsa-ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=DSA CA' dsa-ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=ECDSA CA' ecdsa-ca"
        rlRun "x509CertSign --CA rsa-ca rsa-server"
        rlRun "x509CertSign --CA dsa-ca dsa-server"
        rlRun "x509CertSign --CA dsa-ca dsa-server-1024"
        rlRun "x509CertSign --CA ecdsa-ca ecdsa-server"
        rlRun "x509CertSign --CA rsa-ca -t webclient rsa-client"
        rlRun "x509CertSign --CA dsa-ca -t webclient dsa-client"
        rlRun "x509CertSign --CA dsa-ca -t webclient dsa-client-1024"
        rlRun "x509CertSign --CA ecdsa-ca -t webclient ecdsa-client"
        rlRun "x509DumpCert ca" 0 "Root CA"
        rlRun "x509DumpCert rsa-ca" 0 "Intermediate RSA CA"
        rlRun "x509DumpCert dsa-ca" 0 "Intermediate DSA CA"
        rlRun "x509DumpCert ecdsa-ca" 0 "Intermediate ECDSA CA"
        rlRun "x509DumpCert rsa-server" 0 "Server RSA certificate"
        rlRun "x509DumpCert dsa-server" 0 "Server DSA certificate"
        rlRun "x509DumpCert dsa-server-1024" 0 "Server DSA certificate (1024-bit)"
        rlRun "x509DumpCert ecdsa-server" 0 "Server ECDSA certificate"
        rlRun "x509DumpCert rsa-client" 0 "Client RSA certificate"
        rlRun "x509DumpCert dsa-client" 0 "Client DSA certificate"
        rlRun "x509DumpCert dsa-client-1024" 0 "Client DSA certificate (1024-bit)"
        rlRun "x509DumpCert ecdsa-client" 0 "Client ECDSA certificate"
        rlLogInfo "Loading configuration..."

        i=0
        # Signature algorithm name
        declare -a S_NAME
        # GnuTLS signature algorithm name
        declare -a S_GNUTLS
        # intermediate CA used
        declare -a S_SUBCA
        # EE certificate used
        declare -a S_CERT
        # EE key used
        declare -a S_KEY

        # References: RFC 5246, Section 7.4.1.4.1

        S_NAME[$i]="DSA-SHA1"
        S_GNUTLS[$i]="SIGN-DSA-SHA1"
        S_OPENSSL[$i]="DSA+SHA1"
        S_SUBCA[$i]="$(x509Cert dsa-ca)"
        S_CERT[$i]="$(x509Cert dsa-server-1024)"
        S_KEY[$i]="$(x509Key dsa-server-1024)"
        S_CLNT_CERT[$i]="$(x509Cert dsa-client-1024)"
        S_CLNT_KEY[$i]="$(x509Key dsa-client-1024)"
        i=$(($i+1))

        S_NAME[$i]="DSA-SHA224"
        S_GNUTLS[$i]="SIGN-DSA-SHA224"
        S_OPENSSL[$i]="DSA+SHA224"
        S_SUBCA[$i]="$(x509Cert dsa-ca)"
        S_CERT[$i]="$(x509Cert dsa-server-1024)"
        S_KEY[$i]="$(x509Key dsa-server-1024)"
        S_CLNT_CERT[$i]="$(x509Cert dsa-client-1024)"
        S_CLNT_KEY[$i]="$(x509Key dsa-client-1024)"
        i=$(($i+1))

        S_NAME[$i]="DSA-SHA256"
        S_GNUTLS[$i]="SIGN-DSA-SHA256"
        S_OPENSSL[$i]="DSA+SHA256"
        S_SUBCA[$i]="$(x509Cert dsa-ca)"
        S_CERT[$i]="$(x509Cert dsa-server)"
        S_KEY[$i]="$(x509Key dsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert dsa-client)"
        S_CLNT_KEY[$i]="$(x509Key dsa-client)"
        i=$(($i+1))

        S_NAME[$i]="RSA-SHA1"
        S_GNUTLS[$i]="SIGN-RSA-SHA1"
        S_OPENSSL[$i]="RSA+SHA1"
        S_SUBCA[$i]="$(x509Cert rsa-ca)"
        S_CERT[$i]="$(x509Cert rsa-server)"
        S_KEY[$i]="$(x509Key rsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        S_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        S_NAME[$i]="RSA-SHA224"
        S_GNUTLS[$i]="SIGN-RSA-SHA224"
        S_OPENSSL[$i]="RSA+SHA224"
        S_SUBCA[$i]="$(x509Cert rsa-ca)"
        S_CERT[$i]="$(x509Cert rsa-server)"
        S_KEY[$i]="$(x509Key rsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        S_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        S_NAME[$i]="RSA-SHA256"
        S_GNUTLS[$i]="SIGN-RSA-SHA256"
        S_OPENSSL[$i]="RSA+SHA256"
        S_SUBCA[$i]="$(x509Cert rsa-ca)"
        S_CERT[$i]="$(x509Cert rsa-server)"
        S_KEY[$i]="$(x509Key rsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        S_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        S_NAME[$i]="RSA-SHA384"
        S_GNUTLS[$i]="SIGN-RSA-SHA384"
        S_OPENSSL[$i]="RSA+SHA384"
        S_SUBCA[$i]="$(x509Cert rsa-ca)"
        S_CERT[$i]="$(x509Cert rsa-server)"
        S_KEY[$i]="$(x509Key rsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        S_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        S_NAME[$i]="RSA-SHA512"
        S_GNUTLS[$i]="SIGN-RSA-SHA512"
        S_OPENSSL[$i]="RSA+SHA512"
        S_SUBCA[$i]="$(x509Cert rsa-ca)"
        S_CERT[$i]="$(x509Cert rsa-server)"
        S_KEY[$i]="$(x509Key rsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        S_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        S_NAME[$i]="ECDSA-SHA1"
        S_GNUTLS[$i]="SIGN-ECDSA-SHA1"
        S_OPENSSL[$i]="ECDSA+SHA1"
        S_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        S_CERT[$i]="$(x509Cert ecdsa-server)"
        S_KEY[$i]="$(x509Key ecdsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        S_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        S_NAME[$i]="ECDSA-SHA224"
        S_GNUTLS[$i]="SIGN-ECDSA-SHA224"
        S_OPENSSL[$i]="ECDSA+SHA224"
        S_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        S_CERT[$i]="$(x509Cert ecdsa-server)"
        S_KEY[$i]="$(x509Key ecdsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        S_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        S_NAME[$i]="ECDSA-SHA256"
        S_GNUTLS[$i]="SIGN-ECDSA-SHA256"
        S_OPENSSL[$i]="ECDSA+SHA256"
        S_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        S_CERT[$i]="$(x509Cert ecdsa-server)"
        S_KEY[$i]="$(x509Key ecdsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        S_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        S_NAME[$i]="ECDSA-SHA384"
        S_GNUTLS[$i]="SIGN-ECDSA-SHA384"
        S_OPENSSL[$i]="ECDSA+SHA384"
        S_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        S_CERT[$i]="$(x509Cert ecdsa-server)"
        S_KEY[$i]="$(x509Key ecdsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        S_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        S_NAME[$i]="ECDSA-SHA512"
        S_GNUTLS[$i]="SIGN-ECDSA-SHA512"
        S_OPENSSL[$i]="ECDSA+SHA512"
        S_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        S_CERT[$i]="$(x509Cert ecdsa-server)"
        S_KEY[$i]="$(x509Key ecdsa-server)"
        S_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        S_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

    rlPhaseEnd

    # signature_algorithms extension is supported only in TLSv1.2
    for idx in ${!S_NAME[@]}; do
        rlPhaseStartTest "GnuTLS <-> OpenSSL [${S_NAME[$idx]}]"
            # GnuTLS server setup
            options=(gnutls-serv --port 4433 --http --x509keyfile ${S_KEY[$idx]})
            options+=(--x509cafile '<(cat $(x509Cert ca) ${S_SUBCA[$idx]})')
            options+=(--x509certfile '<(cat ${S_CERT[$idx]} ${S_SUBCA[$idx]})')
            options+=(--priority ${GNUTLS_PROFILE}:+${S_GNUTLS[$idx]})
            rlRun "${options[*]} >server.log 2>server.err &"
            gnutls_pid=$!
            rlRun "rlWaitForSocket -p $gnutls_pid 4433"

            # OpenSSL client setup
            options=(openssl s_client -connect localhost:4433)
            options+=(-CAfile $(x509Cert ca) -tls1_2)
            options+=(-sigalgs ${S_OPENSSL[$idx]})
            rlRun "${options[*]} <<< 'GET / HTTP/1.1'"
            rlAssertGrep "Server Signature: ${S_NAME[$idx]}" server.log

            rlRun "kill $gnutls_pid"
            rlRun "rlWait -s 9 $gnutls_pid" 143,1
            if ! rlGetPhaseState; then
                rlRun "cat server.log"
                rlRun "cat server.err"
            fi
        rlPhaseEnd

        rlPhaseStartTest "GnuTLS <-> OpenSSL [${S_NAME[$idx]}, client auth]"
            # GnuTLS server setup
            options=(gnutls-serv --port 4433 --http --x509keyfile ${S_KEY[$idx]})
            options+=(--x509cafile '<(cat $(x509Cert ca) ${S_SUBCA[$idx]})')
            options+=(--x509certfile '<(cat ${S_CERT[$idx]} ${S_SUBCA[$idx]})')
            options+=(--priority ${GNUTLS_PROFILE}:+${S_GNUTLS[$idx]})
            options+=(--require-client-cert --verify-client-cert)
            rlRun "${options[*]} >server.log 2>server.err &"
            gnutls_pid=$!
            rlRun "rlWaitForSocket -p $gnutls_pid 4433"

            # OpenSSL client setup
            options=(openssl s_client -connect localhost:4433)
            options+=(-CAfile $(x509Cert ca) -tls1_2)
            options+=(-sigalgs ${S_OPENSSL[$idx]})
            options+=(-client_sigalgs ${S_OPENSSL[$idx]})
            options+=(-cert ${S_CLNT_CERT[$idx]} -key ${S_CLNT_KEY[$idx]})
            rlRun "${options[*]} <<< 'GET / HTTP/1.1'"
            rlAssertGrep "Server Signature: ${S_NAME[$idx]}" server.log
            rlAssertGrep "Client Signature: ${S_NAME[$idx]}" server.log

            rlRun "kill $gnutls_pid"
            rlRun "rlWait -s 9 $gnutls_pid" 143,1
            if ! rlGetPhaseState; then
                rlRun "cat server.log"
                rlRun "cat server.err"
            fi
        rlPhaseEnd

        rlPhaseStartTest "OpenSSL <-> GnuTLS [${S_NAME[$idx]}]"
            # OpenSSL server setup
            options=(openssl s_server -www -key ${S_KEY[$idx]})
            options+=(-cert ${S_CERT[$idx]} -tls1_2)
            options+=(-sigalgs ${S_OPENSSL[$idx]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${S_SUBCA[$idx]})')
            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"

            # GnuTLS client setup
            options=(gnutls-cli -p 4433 --x509cafile $(x509Cert ca))
            options+=(--priority ${GNUTLS_PROFILE}:+${S_GNUTLS[$idx]})
            rlRun -s "${options[*]} localhost <<< 'GET / HTTP/1.1'"
            rlAssertGrep "Server Signature: ${S_NAME[$idx]}" "$rlRun_LOG"

            rlRun "kill $openssl_pid"
            rlRun "rlWait -s 9 $openssl_pid" 143,1
            if ! rlGetPhaseState; then
                rlRun "cat server.log"
                rlRun "cat server.err"
            fi
        rlPhaseEnd

        rlPhaseStartTest "OpenSSL <-> GnuTLS [${S_NAME[$idx]}, client auth]"
            # OpenSSL server setup
            options=(openssl s_server -www -key ${S_KEY[$idx]})
            options+=(-cert ${S_CERT[$idx]} -tls1_2)
            options+=(-sigalgs ${S_OPENSSL[$idx]})
            options+=(-client_sigalgs ${S_OPENSSL[$idx]})
            options+=(-CAfile '<(cat $(x509Cert ca) ${S_SUBCA[$idx]})')
            options+=(-Verify 1 -verify_return_error)
            rlRun "${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"

            # GnuTLS client setup
            options=(gnutls-cli -p 4433)
            options+=(--x509cafile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(--priority ${GNUTLS_PROFILE}:+${S_GNUTLS[$idx]})
            options+=(--x509certfile ${S_CLNT_CERT[$idx]})
            options+=(--x509keyfile ${S_CLNT_KEY[$idx]})

            rlRun -s "${options[*]} localhost <<< 'GET / HTTP/1.1'"
            rlAssertGrep "Server Signature: ${S_NAME[$idx]}" "$rlRun_LOG"
            rlAssertGrep "Client Signature: ${S_NAME[$idx]}" "$rlRun_LOG"

            rlRun "kill $openssl_pid"
            rlRun "rlWait -s 9 $openssl_pid" 143,1
            if ! rlGetPhaseState; then
                rlRun "cat server.log"
                rlRun "cat server.err"
            fi
        rlPhaseEnd
    done

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd

rlJournalPrintText
rlJournalEnd
rlGetTestState
