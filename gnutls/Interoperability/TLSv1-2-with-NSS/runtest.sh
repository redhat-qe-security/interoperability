#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/gnutls/Interoperability/TLSv1-2-with-NSS
#   Description: Verify interoperability of GnuTLS TLSv1.2 with NSS
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
PACKAGES="openssl gnutls nss"

SERVER_UTIL="/usr/lib/nss/unsupported-tools/selfserv"
CLIENT_UTIL="/usr/lib/nss/unsupported-tools/tstclnt"
[ -f /usr/lib64/nss/unsupported-tools/selfserv ] && SERVER_UTIL="/usr/lib64/nss/unsupported-tools/selfserv"
[ -f /usr/lib64/nss/unsupported-tools/tstclnt ] && CLIENT_UTIL="/usr/lib64/nss/unsupported-tools/tstclnt"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "rlImport openssl/certgen"
        rlRun "rlImport distribution/fips"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "cp gnutls-client.expect nss-server.expect nss-client.expect $TmpDir"
        rlRun "pushd $TmpDir"
        # in FIPS mode by default in testing we don't allow OpenSSL to generate
        # 1024 bit keys, but since we're not testing OpenSSL and we're
        # verifying that legacy code works, we can override this system wide
        # setting
        unset OPENSSL_ENFORCE_MODULUS_BITS
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
        if ! fipsIsEnabled; then
            C_NAME[$i]="TLS_RSA_WITH_RC4_128_MD5"
            C_OPENSSL[$i]="RC4-MD5"
            C_ID[$i]="0004"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_RSA_WITH_RC4_128_SHA"
            C_OPENSSL[$i]="RC4-SHA"
            C_ID[$i]="0005"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
            C_OPENSSL[$i]="CAMELLIA128-SHA"
            C_ID[$i]="0041"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
            C_OPENSSL[$i]="CAMELLIA256-SHA"
            C_ID[$i]="0084"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

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

        if ! fipsIsEnabled; then
            C_NAME[$i]="TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"
            C_OPENSSL[$i]="DHE-RSA-CAMELLIA128-SHA"
            C_ID[$i]="0045"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"
            C_OPENSSL[$i]="DHE-RSA-CAMELLIA256-SHA"
            C_ID[$i]="0088"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert rsa-ca)"
            C_CERT[$i]="$(x509Cert rsa-server)"
            C_KEY[$i]="$(x509Key rsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert rsa-client)"
            C_CLNT_KEY[$i]="$(x509Key rsa-client)"
            i=$(($i+1))
        fi

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
        # for cipher suites, RHBZ#1238333

        if ! fipsIsEnabled; then
            C_NAME[$i]="TLS_DHE_DSS_WITH_RC4_128_SHA"
            C_OPENSSL[$i]="DHE-DSS-RC4-SHA"
            C_ID[$i]="0066"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
            C_CERT[$i]="$(x509Cert 1024dsa-server)"
            C_KEY[$i]="$(x509Key 1024dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
            C_OPENSSL[$i]="DHE-DSS-CAMELLIA128-SHA"
            C_ID[$i]="0044"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
            C_CERT[$i]="$(x509Cert 1024dsa-server)"
            C_KEY[$i]="$(x509Key 1024dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
            i=$(($i+1))

            C_NAME[$i]="TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"
            C_OPENSSL[$i]="DHE-DSS-CAMELLIA256-SHA"
            C_ID[$i]="0087"
            C_TLS1_2_ONLY[$i]="False"
            C_SUBCA[$i]="$(x509Cert 1024dsa-ca)"
            C_CERT[$i]="$(x509Cert 1024dsa-server)"
            C_KEY[$i]="$(x509Key 1024dsa-server)"
            C_CLNT_CERT[$i]="$(x509Cert 1024dsa-client)"
            C_CLNT_KEY[$i]="$(x509Key 1024dsa-client)"
            i=$(($i+1))
        fi

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

        rlRun "mkdir ca-db" 0 "Directory with just CA certificate"
        rlRun "certutil -N --empty-password -d sql:./ca-db" 0 "Create database for CA cert"
        rlRun "certutil -A -d sql:./ca-db -n ca -t 'cC,,' -a -i $(x509Cert ca)"\
            0 "Import CA certificate"
    rlPhaseEnd

    for j in ${!C_NAME[@]}; do
      for prot in tls1_2 tls1_1; do

        # skip ciphers which work only in TLS1.2 protocol when testing TLS1.1
        if [[ $prot == "tls1_1" ]] && [[ ${C_TLS1_2_ONLY[$j]} == "True" ]]; then
            continue
        fi

        rlPhaseStartTest "GnuTLS server NSS client ${C_NAME[$j]} cipher $prot protocol"
            options=(gnutls-serv --http -p 4433)
            options+=(--x509keyfile ${C_KEY[$j]})
            options+=(--x509certfile "<(cat ${C_CERT[$j]} ${C_SUBCA[$j]})")
            options+=(--priority NORMAL:+VERS-TLS1.2)
            options+=(">server.log" "2>server.err" "&")
            rlRun "${options[*]}"
            gnutls_pid=$!
            rlRun "rlWaitForSocket 4433 -p $gnutls_pid"
            options=(${CLIENT_UTIL})
            options+=(-h localhost -p 4433)
            options+=(-d sql:./ca-db/ -c :${C_ID[$j]})
            if rlIsRHEL 6; then
                options+=(-4)
            fi
            if [[ $prot == "tls1_2" ]]; then
                options+=(-V tls1.0:)
            else
                options+=(-V tls1.0:tls1.1)
            fi
            rlRun -s "expect nss-client.expect ${options[*]}"
            rlAssertGrep "GET / HTTP/1.0" "$rlRun_LOG"
            rlAssertGrep "HTTP/1.0 200 OK" "$rlRun_LOG"
            if [[ $prot == tls1_2 ]]; then
                rlAssertGrep "Version: TLS1.2" server.log
            else
                rlAssertGrep "Version: TLS1.1" server.log
            fi
            rlRun "kill $gnutls_pid"
            rlRun "rlWait -s 9 $gnutls_pid" 0-255
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
        rlPhaseEnd

        rlPhaseStartTest "NSS server GnuTLS client ${C_NAME[$j]} cipher $prot protocol"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cC,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$j]%%/*}) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            declare -a options=()
            options+=(${SERVER_UTIL} -d sql:./nssdb/ -p 4433 -V tls1.0:
                      -c :${C_ID[$j]} -H 1)

            # ecdsa certs require different option to specify used key
            if [[ ${C_KEY[$j]} =~ 'ecdsa' ]]; then
                options+=(-e ${C_KEY[$j]%%/*})
            elif [[ ${C_KEY[$j]} =~ 'dsa' ]]; then
                options+=(-S ${C_KEY[$j]%%/*})
            else
                options+=(-n ${C_KEY[$j]%%/*})
            fi
            rlRun "expect nss-server.expect ${options[*]} >server.log 2>server.err &"
            nss_pid=$!
            rlRun "rlWaitForSocket 4433 -p $nss_pid"
            options=(gnutls-cli)
            options+=(--x509cafile $(x509Cert ca))
            options+=(-p 4433 localhost)
            if [[ $prot == "tls1_2" ]]; then
                options+=(--priority NORMAL:+VERS-TLS1.2)
            else
                options+=(--priority NORMAL:-VERS-TLS1.2)
            fi
            rlRun -s "expect gnutls-client.expect ${options[*]}"
            rlAssertGrep "GET / HTTP/1.0" $rlRun_LOG
            rlAssertGrep "Server: Generic Web Server" $rlRun_LOG
            if [[ $prot == tls1_2 ]]; then
                rlAssertGrep "Version: TLS1.2" $rlRun_LOG
            else
                rlAssertGrep "Version: TLS1.1" $rlRun_LOG
            fi
            rlRun "kill $nss_pid"
            rlRun "rlWait -s 9 $nss_pid" 0-255
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/" 0 "Clean up NSS database"
        rlPhaseEnd

        rlPhaseStartTest "GnuTLS server NSS client ${C_NAME[$j]} cipher $prot protocol client cert"
            rlLogInfo "Prepare nss db for client"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb"
            rlRun "certutil -A -d sql:./nssdb -n ca -t 'cCT,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            nickname="${C_CLNT_KEY[$j]%%/*}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_CLNT_KEY[$j]%%/*}) -d sql:./nssdb -W ''" 0 "Import client certificate"
            rlRun "certutil -L -d sql:./nssdb"

            rlLogInfo "Test proper"
            options=(--http -p 4433)
            options+=(--priority NORMAL:+VERS-TLS1.2)
            options+=(--x509keyfile ${C_KEY[$j]})
            options+=(--x509certfile '<(cat ${C_CERT[$j]} ${C_SUBCA[$j]})')
            options+=(--x509cafile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            if rlIsRHEL 6; then
                options+=(--require-cert)
            else
                options+=(--require-client-cert --verify-client-cert)
            fi
            rlRun "gnutls-serv ${options[*]} >server.log 2>server.err &"
            openssl_pid=$!
            rlRun "rlWaitForSocket 4433 -p $openssl_pid"

            options=(${CLIENT_UTIL})
            options+=(-h localhost -p 4433)
            options+=(-d sql:./nssdb/)
            options+=(-n $nickname)
            options+=(-c :${C_ID[$j]})
            if rlIsRHEL 6; then
                # there are some problems with IPv6 connections and hostname
                # resolution on RHEL 6
                options+=(-4)
            fi
            if [[ $prot == "tls1_2" ]]; then
                options+=(-V tls1.0:)
            else
                options+=(-V tls1.0:tls1.1)
            fi
            rlRun -s "expect nss-client.expect ${options[*]}"
            rlAssertGrep "GET / HTTP/1.0" "$rlRun_LOG"
            rlAssertGrep "HTTP/1.0 200 OK" "$rlRun_LOG"
            if [[ $prot == tls1_2 ]]; then
                rlAssertGrep "Version: TLS1.2" server.log
            else
                rlAssertGrep "Version: TLS1.1" server.log
            fi
            rlRun "kill $openssl_pid"
            rlRun "rlWait -s 9 $openssl_pid" 0-255
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb"
        rlPhaseEnd

        rlPhaseStartTest "NSS server GnuTLS client ${C_NAME[$j]} cipher $prot protocol client cert"
            rlLogInfo "Preparing NSS database"
            rlRun "mkdir nssdb/"
            rlRun "certutil -N --empty-password -d sql:./nssdb/"
            rlRun "certutil -A -d sql:./nssdb/ -n ca -t 'cCT,,' -a -i $(x509Cert ca)"
            rlRun "certutil -A -d sql:./nssdb/ -n subca -t ',,' -a -i ${C_SUBCA[$j]}"
            rlRun "pk12util -i $(x509Key --pkcs12 --with-cert ${C_KEY[$j]%%/*}) -d sql:./nssdb -W ''"

            rlLogInfo "Test proper"
            declare -a options=()
            options+=(${SERVER_UTIL})
            options+=(-d sql:./nssdb/)
            options+=(-p 4433 -V tls1.0:)
            options+=(-c :${C_ID[$j]} -H 1)
            options+=(-rr)

            # ecdsa certs require different option to specify used key
            if [[ ${C_KEY[$j]} =~ 'ecdsa' ]]; then
                options+=(-e ${C_KEY[$j]%%/*})
            elif [[ ${C_KEY[$j]} =~ 'dsa' ]]; then
                options+=(-S ${C_KEY[$j]%%/*})
            else
                options+=(-n ${C_KEY[$j]%%/*})
            fi
            rlRun "expect nss-server.expect ${options[*]} >server.log 2>server.err &"
            nss_pid=$!
            rlRun "rlWaitForSocket 4433 -p $nss_pid"
            options=(gnutls-cli)
            options+=(--x509cafile '<(cat $(x509Cert ca) ${C_SUBCA[$j]})')
            options+=(-p 4433 localhost)
            options+=(--x509certfile ${C_CLNT_CERT[$j]})
            options+=(--x509keyfile ${C_CLNT_KEY[$j]})
            if [[ $prot == "tls1_2" ]]; then
                options+=(--priority NORMAL:+VERS-TLS1.2)
            else
                options+=(--priority NORMAL:-VERS-TLS1.2)
            fi
            rlRun -s "expect gnutls-client.expect ${options[*]}"
            rlAssertGrep "GET / HTTP/1.0" $rlRun_LOG
            rlAssertGrep "Server: Generic Web Server" $rlRun_LOG
            if [[ $prot == tls1_2 ]]; then
                rlAssertGrep "Version: TLS1.2" $rlRun_LOG
            else
                rlAssertGrep "Version: TLS1.1" $rlRun_LOG
            fi
            rlRun "kill $nss_pid"
            rlRun "rlWait -s 9 $nss_pid" 0-255
            if ! rlGetPhaseState; then
                rlRun "cat server.log" 0 "Server stdout"
                rlRun "cat server.err" 0 "Server stderr"
            fi
            rlRun "rm -rf nssdb/" 0 "Clean up NSS database"
        rlPhaseEnd
      done
    done

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
rlGetTestState
