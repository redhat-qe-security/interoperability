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
        # C_NSS           NSS ciphersuite ID
        # C_GNUTLS        GNUTLS ciphersuite ID (unused for now)
        # C_TLS1_2_ONLY   new ciphersuite in TLS1.2
        # C_SUBCA         intermediate CA
        # C_CERT          EE (end-entity) certificate
        # C_KEY           EE key
        # C_CLNT_CERT     client certificate
        # C_CLNT_KEY      client key
        i=0

        C_NAME[$i]="TLS_RSA_WITH_AES_128_CBC_SHA"
        C_NSS[$i]="002F"
        C_GNUTLS[$i]="TLS_RSA_AES_128_CBC_SHA1"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_256_CBC_SHA256"
        C_NSS[$i]="003D"
        C_GNUTLS[$i]="TLS_RSA_AES_256_CBC_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_RSA_WITH_AES_128_GCM_SHA256"
        C_NSS[$i]="009C"
        C_GNUTLS[$i]="TLS_RSA_AES_128_GCM_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        # NSS on RHEL-6 does not support SHA-384 PRF
        if ! rlIsRHEL 6; then
            C_NAME[$i]="TLS_RSA_WITH_AES_256_GCM_SHA384"
            C_NSS[$i]="009D"
            C_GNUTLS[$i]="TLS_RSA_AES_256_GCM_SHA384"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
        C_NSS[$i]="0033"
        C_GNUTLS[$i]="TLS_DHE_RSA_AES_128_CBC_SHA1"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
        C_NSS[$i]="006B"
        C_GNUTLS[$i]="TLS_DHE_RSA_AES_256_CBC_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert rsa-ca)"
        C_CERT[$i]="$(x509Cert rsa-server)"
        C_KEY[$i]="$(x509Key rsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
        C_CLNT_KEY[$i]="$(x509Key rsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        C_NSS[$i]="009E"
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
            C_NSS[$i]="009F"
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
        C_NSS[$i]="0032"
        C_GNUTLS[$i]="TLS_DHE_DSS_AES_128_CBC_SHA1"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key dsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
        C_NSS[$i]="006A"
        C_GNUTLS[$i]="TLS_DHE_DSS_AES_256_CBC_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert dsa-ca)"
        C_CERT[$i]="$(x509Cert dsa-server)"
        C_KEY[$i]="$(x509Key dsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert dsa-client)"
        C_CLNT_KEY[$i]="$(x509Key dsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
        C_NSS[$i]="00A2"
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
            C_NSS[$i]="00A3"
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
        C_NSS[$i]="C012"
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
            C_NSS[$i]="C028"
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
        C_NSS[$i]="C02F"
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
            C_NSS[$i]="C030"
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
        C_NSS[$i]="C00A"
        C_GNUTLS[$i]="TLS_ECDHE_ECDSA_AES_256_CBC_SHA1"
        C_TLS1_2_ONLY[$i]="False"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
        C_NSS[$i]="C023"
        C_GNUTLS[$i]="TLS_ECDHE_ECDSA_AES_128_CBC_SHA256"
        C_TLS1_2_ONLY[$i]="True"
        C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
        C_CERT[$i]="$(x509Cert ecdsa-server)"
        C_KEY[$i]="$(x509Key ecdsa-server)"
        C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
        C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
        i=$(($i+1))

        C_NAME[$i]="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        C_NSS[$i]="C02B"
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
            C_NSS[$i]="C02C"
            C_GNUTLS[$i]="TLS_ECDHE_ECDSA_AES_256_GCM_SHA384"
            C_TLS1_2_ONLY[$i]="True"
            C_SUBCA[$i]="$(x509Cert ecdsa-ca)"
            C_CERT[$i]="$(x509Cert ecdsa-server)"
            C_KEY[$i]="$(x509Key ecdsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert ecdsa-client)"
            C_CLNT_KEY[$i]="$(x509Key ecdsa-client)"
            i=$(($i+1))
        fi

        # NSS CA-cert DB
        rlRun "mkdir nss-ca-db" 0 "Directory with just CA certificate"
        rlRun "certutil -N --empty-password -d sql:./nss-ca-db" 0 "Create database for CA cert"
        rlRun "certutil -A -d sql:./nss-ca-db -n ca -t 'cC,,' -a -i $(x509Cert ca)"
    rlPhaseEnd

    for idx in ${!C_NAME[@]}; do
        for proto in tls1_2 tls1_1; do

            # skip tests of TLSv1.2 specific ciphers when testing TLSv1.1
            if [[ $proto == "tls1_1" ]] && [[ ${C_TLS1_2_ONLY[$idx]} == "True" ]]; then
                continue
            fi

            for sess_type in sessionID ticket; do
            rlPhaseStartTest "NSS <-> GNUTLS [${C_NAME[$idx]}, $proto, $sess_type]"
                # NSS server DB
                rlRun "mkdir nssdb/"
                rlRun "certutil -N --empty-password -d sql:./nssdb/"
                rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cC,,' -a -i $(x509Cert ca)"
                rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$idx]}"
                rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$idx]%%/*}) -d sql:./nssdb -W ''"

                # NSS server setup
                options=($SERVER_UTIL -d sql:nssdb -p 4433 -V tls1.0: -H 1)
                options+=(-c :${C_NSS[$idx]})
                if [[ ${C_KEY[$idx]} =~ 'ecdsa' ]]; then
                    options+=(-e ${C_KEY[$idx]%%/*})
                elif [[ ${C_KEY[$idx]} =~ 'dsa' ]]; then
                    options+=(-S ${C_KEY[$idx]%%/*})
                else
                    options+=(-n ${C_KEY[$idx]%%/*})
                fi
                if [[ $sess_type == "ticket" ]]; then
                    options+=(-u)
                fi
                rlRun "${options[*]} >server.log 2>server.err &"
                nss_pid=$!
                rlRun "rlWaitForSocket -p $nss_pid 4433"

                # GNUTLS client setup
                options=(gnutls-cli --resume --x509cafile $(x509Cert ca))
                options+=(--port 4433)
                if [[ $proto == "tls1_1" ]]; then
                    options+=(--priority NORMAL:-VERS-TLS1.2)
                else
                    options+=(--priority NORMAL:+VERS-TLS1.2)
                fi
                rlRun -s "sleep 2 | ${options[*]} localhost"
                rlAssertGrep "This is a resumed session" $rlRun_LOG
                rlAssertNotGrep "failure" $rlRun_LOG -i
                rlRun "kill $nss_pid" 0,1
                rlRun "rlWait -s 9 $nss_pid" 143
                if ! rlGetPhaseState; then
                    rlRun "cat server.log"
                    rlRun "cat server.err"
                fi
                rlRun "rm -fr nssdb"
            rlPhaseEnd

            rlPhaseStartTest "NSS <-> GNUTLS [${C_NAME[$idx]}, $proto, $sess_type, client auth]"
                # NSS DB preparation
                rlRun "mkdir nssdb/"
                rlRun "certutil -N --empty-password -d sql:./nssdb/"
                rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cCT,,' -a -i $(x509Cert ca)"
                rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$idx]}"
                rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$idx]%%/*}) -d sql:./nssdb -W ''"

                # NSS server setup
                options=($SERVER_UTIL -d sql:nssdb -p 4433 -V tls1.0: -H 1 -rr)
                options+=(-c :${C_NSS[$idx]})
                if [[ ${C_KEY[$idx]} =~ 'ecdsa' ]]; then
                    options+=(-e ${C_KEY[$idx]%%/*})
                elif [[ ${C_KEY[$idx]} =~ 'dsa' ]]; then
                    options+=(-S ${C_KEY[$idx]%%/*})
                else
                    options+=(-n ${C_KEY[$idx]%%/*})
                fi
                if [[ $sess_type == "ticket" ]]; then
                    options+=(-u)
                fi
                rlRun "${options[*]} >server.log 2>server.err &"
                nss_pid=$!
                rlRun "rlWaitForSocket -p $nss_pid 4433"

                # GNUTLS client setup
                options=(gnutls-cli --resume)
                options+=(--x509cafile '<(cat $(x509Cert ca) ${C_SUBCA[$idx]})')
                options+=(--x509keyfile ${C_CLNT_KEY[$idx]})
                options+=(--x509certfile ${C_CLNT_CERT[$idx]})
                options+=(--port 4433)
                if [[ $proto == "tls1_1" ]]; then
                    options+=(--priority NORMAL:-VERS-TLS1.2)
                else
                    options+=(--priority NORMAL:+VERS-TLS1.2)
                fi
                rlRun -s "sleep 2 | ${options[*]} localhost"
                rlAssertGrep "This is a resumed session" $rlRun_LOG
                rlAssertNotGrep "failure" $rlRun_LOG -i
                rlRun "kill $nss_pid" 0,1
                rlRun "rlWait -s 9 $nss_pid" 143
                if ! rlGetPhaseState; then
                    rlRun "cat server.log"
                    rlRun "cat server.err"
                fi
                rlRun "rm -fr nssdb"
            rlPhaseEnd

            rlPhaseStartTest "GNUTLS <-> NSS [${C_NAME[$idx]}, $proto, $sess_type]"
                # GNUTLS server setup
                options=(gnutls-serv --http --port 4433)
                options+=(--priority NORMAL:+VERS-TLS1.2)
                options+=(--x509keyfile ${C_KEY[$idx]})
                options+=(--x509certfile '<(cat ${C_CERT[$idx]} ${C_SUBCA[$idx]})')
                rlRun "${options[*]} >server.log 2>server.err &"
                gnutls_pid=$!
                rlRun "rlWaitForSocket -p $gnutls_pid 4433"

                # NSS client setup
                options=($CLIENT_UTIL -p 4433 -d sql:nss-ca-db -c 100 -P 20)
                options+=(-C :${C_NSS[$idx]})
                if [[ $proto == "tls1_2" ]]; then
                    options+=(-V tls1.0:)
                else
                    options+=(-V tls1.0:tls1.1)
                fi
                if [[ $sess_type == "ticket" ]]; then
                    options+=(-u)
                fi
                rlRun -s "${options[*]} localhost" 1
                rlAssertGrep "80 cache hits" "$rlRun_LOG"
                if [[ $sess_type == "ticket" ]]; then
                    rlAssertGrep "80 stateless resumes" $rlRun_LOG
                else
                    rlAssertGrep "0 stateless resumes" $rlRun_LOG
                fi
                rlRun "kill $gnutls_pid" 0,1
                rlRun "rlWait -s 9 $gnutls_pid" 143,1
                if ! rlGetPhaseState; then
                    rlRun "cat server.log"
                    rlRun "cat server.err"
                fi
            rlPhaseEnd

            # strsclnt can't handle client certificates (yet)
            if false; then
            rlPhaseStartTest "GNUTLS <-> NSS [${C_NAME[$idx]}, $proto, $sess_type, client auth]"
                # NSS client DB
                rlRun "mkdir nssdb/"
                rlRun "certutil -N --empty-password -d sql:./nssdb"
                rlRun "certutil -A -d sql:./nssdb -n ca -t 'cCT,,' -a -i $(x509Cert ca)"
                rlRun "certutil -A -d sql:./nssdb -n subca -t ',,' -a -i ${C_SUBCA[$idx]}"
                clnt_nickname="${C_CLNT_KEY[$idx]%%/*}"
                rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_CLNT_KEY[$idx]%%/*}) -d sql:./nssdb -W ''"
                rlRun "certutil -L -d sql:./nssdb"

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

                # NSS client setup
                options=($CLIENT_UTIL -p 4433 -d sql:nssdb -c 100 -P 20)
                options+=(-C :${C_NSS[$idx]} -n $clnt_nickname)
                if [[ $proto == "tls1_2" ]]; then
                    options+=(-V tls1.0:)
                else
                    options+=(-V tls1.0:tls1.1)
                fi
                if [[ $sess_type == "ticket" ]]; then
                    options+=(-u)
                fi
                rlRun -s "${options[*]} localhost" 1
                rlAssertGrep "80 cache hits" "$rlRun_LOG"
                if [[ $sess_type == "ticket" ]]; then
                    rlAssertGrep "80 stateless resumes" $rlRun_LOG
                else
                    rlAssertGrep "0 stateless resumes" $rlRun_LOG
                fi
                rlRun "kill $gnutls_pid" 0,1
                rlRun "rlWait -s 9 $gnutls_pid" 143,1
                if ! rlGetPhaseState; then
                    rlRun "cat server.log"
                    rlRun "cat server.err"
                fi
                rlRun "rm -fr nssdb"
            rlPhaseEnd
            fi
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
