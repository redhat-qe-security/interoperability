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
        rlRun "rlImport openssl/certgen"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen rsa-ca"
        rlRun "x509KeyGen -t dsa dsa-ca"
        rlRun "x509KeyGen -t ecdsa ecdsa-ca"
        rlRun "x509KeyGen rsa-server"
        rlRun "x509KeyGen -t dsa dsa-server"
        rlRun "x509KeyGen -t ecdsa ecdsa-server"
        rlRun "x509KeyGen rsa-client"
        rlRun "x509KeyGen -t dsa dsa-client"
        rlRun "x509KeyGen -t ecdsa ecdsa-client"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=RSA CA' rsa-ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=DSA CA' dsa-ca"
        rlRun "x509CertSign --CA ca -t ca --DN 'CN=ECDSA CA' ecdsa-ca"
        rlRun "x509CertSign --CA rsa-ca rsa-server"
        rlRun "x509CertSign --CA dsa-ca dsa-server"
        rlRun "x509CertSign --CA ecdsa-ca ecdsa-server"
        rlRun "x509CertSign --CA rsa-ca -t webclient rsa-client"
        rlRun "x509CertSign --CA dsa-ca -t webclient dsa-client"
        rlRun "x509CertSign --CA ecdsa-ca -t webclient ecdsa-client"
        rlRun "x509DumpCert ca" 0 "Root CA"
        rlRun "x509DumpCert rsa-ca" 0 "Intermediate RSA CA"
        rlRun "x509DumpCert dsa-ca" 0 "Intermediate DSA CA"
        rlRun "x509DumpCert ecdsa-ca" 0 "Intermediate ECDSA CA"
        rlRun "x509DumpCert rsa-server" 0 "Server RSA certificate"
        rlRun "x509DumpCert dsa-server" 0 "Server DSA certificate"
        rlRun "x509DumpCert ecdsa-server" 0 "Server ECDSA certificate"
        rlRun "x509DumpCert rsa-client" 0 "Client RSA certificate"
        rlRun "x509DumpCert dsa-client" 0 "Client DSA certificate"
        rlRun "x509DumpCert ecdsa-client" 0 "Client ECDSA certificate"

        # Tested combinations

        # Structure definiton:
        # C_NAME          IETF name of a ciphersuite
        # C_OPENSSL       OpenSSL ciphersuite ID
        # C_GNUTLS        GNUTLS ciphersuite ID (unused for now)
        # C_TLS1_2_ONLY   new ciphersuite in TLS1.2
        # C_SUBCA         intermediate CA
        # C_CERT          EE (end-entity) certificate
        # C_KEY           EE key
        # C_CLNT_CERT     client certificate
        # C_CLNT_KEY      client key
        i=0

        C_NAME[$i]="TLS_RSA_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="AES128-SHA"
        C_GNUTLS[$i]="TLS_RSA_AES_128_CBC_SHA1"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="AES256-SHA256"
        C_GNUTLS[$i]="TLS_RSA_AES_256_CBC_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="AES128-GCM-SHA256"
        C_GNUTLS[$i]="TLS_RSA_AES_128_GCM_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_256_GCM_SHA384"
        C_OPENSSL[$i]="AES256-GCM-SHA384"
        C_GNUTLS[$i]="TLS_RSA_AES_256_GCM_SHA384"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="DHE-RSA-AES128-SHA"
        C_GNUTLS[$i]="TLS_DHE_RSA_AES_128_CBC_SHA1"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="DHE-RSA-AES256-SHA256"
        C_GNUTLS[$i]="TLS_DHE_RSA_AES_256_CBC_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="DHE-RSA-AES128-GCM-SHA256"
        C_GNUTLS[$i]="TLS_DHE_RSA_AES_128_GCM_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
            C_OPENSSL[$i]="DHE-RSA-AES256-GCM-SHA384"
            C_GNUTLS[$i]="TLS_DHE_RSA_AES_256_GCM_SHA384"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
        C_OPENSSL[$i]="DHE-DSS-AES128-SHA"
        C_GNUTLS[$i]="TLS_DHE_DSS_AES_128_CBC_SHA1"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key dsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
        C_OPENSSL[$i]="DHE-DSS-AES256-SHA256"
        C_GNUTLS[$i]="TLS_DHE_DSS_AES_256_CBC_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key dsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="DHE-DSS-AES128-GCM-SHA256"
        C_GNUTLS[$i]="TLS_DHE_DSS_AES_128_GCM_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key dsa-client)"
        i=$(($i+1))

        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
            C_OPENSSL[$i]="DHE-DSS-AES256-GCM-SHA384"
            C_GNUTLS[$i]="TLS_DHE_DSS_AES_256_GCM_SHA384"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert dsa-ca)"
            C_CERT[$i]="$(x509Cert dsa-server)"
            C_KEY[$i]="$(x509Key dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key dsa-client)"
            i=$(($i+1))
        fi

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
        C_OPENSSL[$i]="ECDHE-RSA-DES-CBC3-SHA"
        C_GNUTLS[$i]="TLS_ECDHE_RSA_3DES_EDE_CBC_SHA1"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
            C_OPENSSL[$i]="ECDHE-RSA-AES256-SHA384"
            C_GNUTLS[$i]="TLS_ECDHE_RSA_AES_256_CBC_SHA384"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="ECDHE-RSA-AES128-GCM-SHA256"
        C_GNUTLS[$i]="TLS_ECDHE_RSA_AES_128_GCM_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            C_OPENSSL[$i]="ECDHE-RSA-AES256-GCM-SHA384"
            C_GNUTLS[$i]="TLS_ECDHE_RSA_AES_256_GCM_SHA384"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES256-SHA"
        C_GNUTLS[$i]="TLS_ECDHE_ECDSA_AES_256_CBC_SHA1"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES128-SHA256"
        C_GNUTLS[$i]="TLS_ECDHE_ECDSA_AES_128_CBC_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        C_OPENSSL[$i]="ECDHE-ECDSA-AES128-GCM-SHA256"
        C_GNUTLS[$i]="TLS_ECDHE_ECDSA_AES_128_GCM_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            C_OPENSSL[$i]="ECDHE-ECDSA-AES256-GCM-SHA384"
            C_GNUTLS[$i]="TLS_ECDHE_ECDSA_AES_256_GCM_SHA384"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
            C_CERT[$i]="$(x509Cert ecdsa-server)"
            C_KEY[$i]="$(x509Key ecdsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
            C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
            i=$(($i+1))
        fi

    rlPhaseEnd

    for idx in ${!C_NAME[@]}; do
        for proto in tls1_2 tls1_1; do

            # skip tests of TLSv1.2 specific ciphers when testing TLSv1.1
            if [[ $proto == "tls1_1" ]] && [[ ${C_TLS1_2_ONLY[$idx]} == "True" ]]; then
                continue
            fi

            for sess_type in sessionID ticket; do
            rlPhaseStartTest "OpenSSL <-> GNUTLS [${C_NAME[$idx]}, $proto, $sess_type]"
                # OpenSSL server setup
                options=(openssl s_server -www -key ${C_KEY[$idx]})
                options+=(-cert ${C_CERT[$idx]} -cipher ${C_OPENSSL[$idx]})
                options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$idx]})')
                rlRun "${options[*]} >server.log 2>server.err &"
                openssl_pid=$!
                rlRun "rlWaitForSocket -p $openssl_pid 4433"

                # GNUTLS client setup
                options=(gnutls-cli --resume --port 4433)
                options+=(--x509cafile $(x509Cert ca))
                if [[ $proto == "tls1_1" ]]; then
                    options+=(--priority NORMAL:-VERS-TLS1.2)
                else
                    options+=(--priority NORMAL:+VERS-TLS1.2)
                fi
                if [[ $sess_type == "sessionID" ]]; then
                    options+=(--noticket)
                fi
                rlRun -s "${options[*]} localhost < /dev/null"
                rlAssertGrep "This is a resumed session" $rlRun_LOG
                rlAssertNotGrep "failure" $rlRun_LOG -i
                rlRun "kill $openssl_pid"
                rlRun "rlWait -s 9 $openssl_pid" 143
                if ! rlGetPhaseState; then
                    rlRun "cat server.log"
                    rlRun "cat server.err"
                fi
            rlPhaseEnd

            rlPhaseStartTest "OpenSSL <-> GNUTLS [${C_NAME[$idx]}, $proto, $sess_type, client auth]"
                # OpenSSL server setup
                options=(openssl s_server -www -key ${C_KEY[$idx]})
                options+=(-cert ${C_CERT[$idx]} -cipher ${C_OPENSSL[$idx]})
                options+=(-CAfile '<(cat $(x509Cert ca) ${C_SUBCA[$idx]})')
                options+=(-Verify 1 -verify_return_error)
                rlRun "${options[*]} >server.log 2>server.err &"
                openssl_pid=$!
                rlRun "rlWaitForSocket -p $openssl_pid 4433"

                # GNUTLS client setup
                options=(gnutls-cli --resume --port 4433)
                options+=(--x509cafile '<(cat $(x509Cert ca) ${C_SUBCA[$idx]})')
                options+=(--x509keyfile ${C_CLNT_KEY[$idx]})
                options+=(--x509certfile ${C_CLNT_CERT[$idx]})
                if [[ $proto == "tls1_1" ]]; then
                    options+=(--priority NORMAL:-VERS-TLS1.2)
                else
                    options+=(--priority NORMAL:+VERS-TLS1.2)
                fi
                if [[ $sess_type == "sessionID" ]]; then
                    options+=(--noticket)
                fi
                rlRun -s "${options[*]} localhost < /dev/null"
                rlAssertGrep "This is a resumed session" $rlRun_LOG
                rlAssertNotGrep "failure" $rlRun_LOG -i
                rlRun "kill $openssl_pid"
                rlRun "rlWait -s 9 $openssl_pid" 143
                if ! rlGetPhaseState; then
                    rlRun "cat server.log"
                    rlRun "cat server.err"
                fi
            rlPhaseEnd

            rlPhaseStartTest "GNUTLS <-> OpenSSL [${C_NAME[$idx]}, $proto, $sess_type]"
                # GNUTLS server setup
                options=(gnutls-serv --http --port 4433)
                options+=(--x509keyfile ${C_KEY[$idx]})
                options+=(--x509certfile '<(cat ${C_CERT[$idx]} ${C_SUBCA[$idx]})')
                options+=(--priority NORMAL:+VERS-TLS1.2)
                rlRun "${options[*]} >server.log 2>server.err &"
                gnutls_pid=$!
                rlRun "rlWaitForSocket -p $gnutls_pid 4433"

                # OpenSSL client setup
                options=(openssl s_client -connect localhost:4433)
                options+=(-CAfile $(x509Cert ca) -cipher ${C_OPENSSL[$idx]})
                if [[ $sess_type == "sessionID" ]]; then
                    options+=(-no_ticket)
                fi
                if [[ $proto == "tls1_1" ]]; then
                    options+=(-tls1_1)
                fi
                rlRun -s "${options[*]} -sess_out sess.pem < /dev/null"
                rlAssertGrep "New, TLSv1/SSLv3" $rlRun_LOG
                rlAssertNotGrep "Reused, TLSv1/SSLv3" $rlRun_LOG
                rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
                rlRun -s "${options[*]} -sess_in sess.pem < /dev/null"
                rlAssertGrep "Reused, TLSv1/SSLv3" $rlRun_LOG
                rlAssertNotGrep "New, TLSv1/SSLv3" $rlRun_LOG
                rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
                rlRun "kill $gnutls_pid" 0,1
                rlRun "rlWait -s 9 $gnutls_pid" 143,1
                if ! rlGetPhaseState; then
                    rlRun "cat server.log"
                    rlRun "cat server.err"
                fi
                rlRun "rm sess.pem" 0,1
            rlPhaseEnd

            rlPhaseStartTest "GNUTLS <-> OpenSSL [${C_NAME[$idx]}, $proto, $sess_type, client auth]"
                # GNUTLS server setup
                options=(gnutls-serv --http --port 4433)
                options+=(--x509keyfile ${C_KEY[$idx]})
                options+=(--x509cafile '<(cat $(x509Cert ca) ${C_SUBCA[$idx]})')
                options+=(--x509certfile '<(cat ${C_CERT[$idx]} ${C_SUBCA[$idx]})')
                options+=(--priority NORMAL:+VERS-TLS1.2)
                options+=(--require-client-cert --verify-client-cert)
                rlRun "${options[*]} >server.log 2>server.err &"
                gnutls_pid=$!
                rlRun "rlWaitForSocket -p $gnutls_pid 4433"

                # OpenSSL client setup
                options=(openssl s_client -connect localhost:4433)
                options+=(-CAfile $(x509Cert ca) -cipher ${C_OPENSSL[$idx]})
                options+=(-cert ${C_CLNT_CERT[$idx]} -key ${C_CLNT_KEY[$idx]})
                if [[ $sess_type == "sessionID" ]]; then
                    options+=(-no_ticket)
                fi
                if [[ $proto == "tls1_1" ]]; then
                    options+=(-tls1_1)
                fi
                rlRun -s "${options[*]} -sess_out sess.pem < /dev/null"
                rlAssertGrep "New, TLSv1/SSLv3" $rlRun_LOG
                rlAssertNotGrep "Reused, TLSv1/SSLv3" $rlRun_LOG
                rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
                rlRun -s "${options[*]} -sess_in sess.pem < /dev/null"
                rlAssertGrep "Reused, TLSv1/SSLv3" $rlRun_LOG
                rlAssertNotGrep "New, TLSv1/SSLv3" $rlRun_LOG
                rlAssertGrep "Verify return code: 0 (ok)" $rlRun_LOG
                rlRun "kill $gnutls_pid" 0,1
                rlRun "rlWait -s 9 $gnutls_pid" 143,1
                if ! rlGetPhaseState; then
                    rlRun "cat server.log"
                    rlRun "cat server.err"
                fi
                rlRun "rm sess.pem" 0,1
            rlPhaseEnd
            done
        done
    done

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
rlGetTestState
