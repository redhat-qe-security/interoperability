#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/nss/Interoperability/Interoperability-with-OpenSSL
#   Description: Check if nss and openssl can communicate with each other
#   Author: Hubert Kario <hkario@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2013 Red Hat, Inc. All rights reserved.
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

PACKAGE="nss"
PACKAGES="nss openssl wireshark"

NSS_SERVER="/usr/lib64/nss/unsupported-tools/selfserv"
NSS_CLIENT="/usr/lib64/nss/unsupported-tools/tstclnt"
[ -x $NSS_CLIENT ] || NSS_CLIENT="/usr/lib/nss/unsupported-tools/tstclnt"
[ -x $NSS_SERVER ] || NSS_SERVER="/usr/lib/nss/unsupported-tools/selfserv"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "cp gen-ecca.expect gen-ecsrv.expect gen-rsaca.expect gen-rsasrv.expect make_certs.sh $TmpDir" 0 "Copy cert creation scripts to tmp directory"
        rlRun "pushd $TmpDir"
        rlRun "cat <<EOF > client.in
client hello
EOF" 0 "Create client query file"
        rlRun "cat <<EOF > server.in
server hello
EOF" 0 "Create server query file"
        rlLogInfo "Make nss certificates"
        rlRun "mkdir nss-certs/" 0 "Create directory for nss generated certificates"
        rlRun "echo test > password-is-test.txt" 0 "Make file with password"
        rlRun "certutil -N -d nss-certs/ -f password-is-test.txt" 0 "Create empty NSS trust database"
        rlRun "dd if=/dev/urandom of=random bs=1 count=40" 0 "Create a small random file"
        rlRun "./gen-rsaca.expect" 0 "Generate RSA CA certificate"
        rlRun "dd if=/dev/urandom of=random bs=1 count=40" 0 "Create a small random file"
        rlRun "./gen-rsasrv.expect" 0 "Generate server RSA certificate"
        rlRun "dd if=/dev/urandom of=random bs=1 count=40" 0 "Create a small random file"
        rlRun "./gen-ecca.expect ecca nistp256 SHA1" 0 "Generate EC CA certificate"
        rlRun "dd if=/dev/urandom of=random bs=1 count=40" 0 "Create a small random file"
        rlRun "./gen-ecsrv.expect ecsrv nistp256 SHA1 ecca 'o=EC Testing,cn=localhost'" 0 "Generate server EC certificate"
        rlRun "dd if=/dev/urandom of=random bs=1 count=40" 0 "Create a small random file"
        rlRun "./gen-ecsrv.expect rsaecsrv nistp256 SHA1 rsaca 'o=EC-RSA Testing,cn=localhost'" 0 "Generate server EC certificate signed by RSA CA"
        rlRun "certutil -L -d nss-certs/ -f password-is-test.txt" 0 "Print all certs in database"
        rlLogInfo "Make openssl certificates"
        rlRun "./make_certs.sh"
        rlLogInfo "Export NSS CA certs for use with OpenSSL"
        rlRun "certutil -L -n rsaca -a -d nss-certs/ -f password-is-test.txt > nss-certs/rsaca.pem" 0 "Export RSA CA cert"
        rlRun "certutil -L -n ecca -a -d nss-certs/ -f password-is-test.txt > nss-certs/ecca.pem" 0 "Export EC CA cert"
        rlLogInfo "Import OpenSSL CA certs for use with NSS"
        rlRun "mkdir certdb/" 0 "Create directory for nss database"
        rlRun "certutil -N -d certdb/ -f password-is-test.txt" 0 "Create empty NSS database"
        rlRun "certutil -A -n rsaca -t 'TC,TC,TC' -d certdb -a -i openssl-certs/ca_cert.pem -f password-is-test.txt " 0 "Import RSA CA certificate" 
        rlRun "certutil -A -n ecca -t 'TC,TC,TC' -d certdb -a -i openssl-certs/ca2_cert.pem -f password-is-test.txt " 0 "Import EC CA certificate" 
    rlPhaseEnd

    rlPhaseStartTest "Test default settings with RSA OpenSSL server"
        rlRun "(echo server hello; sleep 2) | openssl s_server -key openssl-certs/rsa_server_key.key -cert openssl-certs/rsa_server_cert.pem > server.log 2> server.err &" 0 "Run server"
        server_pid=$!
        rlRun "kill -s 0 $server_pid" 0 "Check if server is running in background"
        rlRun "tcpdump -i lo -s 0 port 4433 -w capture.pcap 2>&1 > tcpdump.log &"
        tcpdump_pid=$!
        rlRun "$NSS_CLIENT -h localhost -p 4433 -d certdb < client.in > client.log 2> client.err"
        rlRun "kill -s 15 $server_pid" 1 "Kill the server in case the test fails"
        rlRun "wait $server_pid" 0 "Wait for server to be killed"
        rlRun "kill -s 15 $tcpdump_pid" 0 "Kill tcpdump"
        rlRun "wait $tcpdump_pid" 0 "Check if tcpdump was killed"
        rlRun "tshark -o 'ssl.desegment_ssl_records:TRUE' -o 'ssl.keys_list:127.0.0.1,4433,http,openssl-certs/rsa_server_key.key' -o 'ssl.debug_file:rsa_private.log' -r capture.pcap -V > tshark.log" 0 "Decode SSL connection"
        rlAssertGrep "client hello" server.log
        rlAssertGrep "server hello" client.log
        rlRun "grep -iE 'fail|error' server.log && grep -iE 'fail|error' server.err" 1 "Check if there are no errors in server output"
        rlRun "grep -iE 'fail|error' client.log && grep -iE 'fail|error' client.log" 1 "Check if there are no errors in client output"
        rlRun "grep 'Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA' tshark.log" 0 "Verify that the negotiated cipher is the most secure supported by client by default"
        rlRun "grep 'TLSv1.2 Record Layer' tshark.log" 0 "Verify that the connection uses TLS1.2"
        echo "============= server.log follows ================"
        cat server.log
        echo "============= server.err follows ================"
        cat server.err
        echo "============= client.log follows ================"
        cat client.log
        echo "============= client.err follows ================"
        cat client.err
        echo "============= tcpdump.log follows ==============="
        cat tcpdump.log
#        echo "======== tshark rsa_prive.log follows ==========="
#        cat rsa_private.log
#        echo "============= tshark.log follows ================"
#        cat tshark.log
    rlPhaseEnd

    rlPhaseStartTest "Test default settings with RSA OpenSSL client"
        rlRun "$NSS_SERVER -n rsasrv -p 4433 -d nss-certs/ -f password-is-test.txt < server.in > server.log 2> server.err &" 0 "Run server"
        server_pid=$!
        rlRun "kill -s 0 $server_pid" 0 "Check if server is running in background"
        rlRun "tcpdump -i lo -s 0 port 4433 -w capture.pcap 2>&1 > tcpdump.log &"
        tcpdump_pid=$!
        rlRun "(echo client hello; sleep 1) | openssl s_client -connect localhost:4433 -CAfile nss-certs/rsaca.pem > client.log 2> client.err"
        rlRun "kill -s 15 $server_pid" 1 "Kill the server in case the test fails"
        rlRun "wait $server_pid" 0 "Wait for server to be killed"
        rlRun "kill -s 15 $tcpdump_pid" 0 "Kill tcpdump"
        rlRun "wait $tcpdump_pid" 0 "Check if tcpdump was killed"
        rlRun "tshark -o 'ssl.desegment_ssl_records:TRUE' -r capture.pcap -V > tshark.log" 0 "Decode SSL connection"
        rlAssertGrep "client hello" server.log
        rlAssertGrep "server hello" client.log
        rlRun "grep -iE 'fail|error' server.log && grep -iE 'fail|error' server.err" 1 "Check if there are no errors in server output"
        rlRun "grep -iE 'fail|error' client.log && grep -iE 'fail|error' client.log" 1 "Check if there are no errors in client output"
        rlRun "grep 'Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA' tshark.log" 0 "Verify that the negotiated cipher is the most secure supported by client by default"
        rlRun "grep 'TLSv1.2 Record Layer' tshark.log" 0 "Verify that the connection uses TLS1.2"
        echo "============= server.log follows ================"
        cat server.log
        echo "============= server.err follows ================"
        cat server.err
        echo "============= client.log follows ================"
        cat client.log
        echo "============= client.err follows ================"
        cat client.err
        echo "============= tcpdump.log follows ==============="
        cat tcpdump.log
#        echo "======== tshark rsa_prive.log follows ==========="
#        cat rsa_private.log
#        echo "============= tshark.log follows ================"
#        cat tshark.log
    rlPhaseEnd

C_NAME[1]="ECDHE-ECDSA-AES256-GCM-SHA384"
C_HEXID[1]="C02C"
C_NAME[2]="ECDHE-ECDSA-AES256-SHA384"
C_HEXID[2]="C024"
C_NAME[3]="ECDHE-ECDSA-AES256-SHA"
C_HEXID[3]="C00A"
C_NAME[4]="ECDH-ECDSA-AES256-GCM-SHA384"
C_HEXID[4]="C02E"
C_NAME[5]="ECDH-ECDSA-AES256-SHA384"
C_HEXID[5]="C026"
C_NAME[6]="ECDH-ECDSA-AES256-SHA"
C_HEXID[6]="C005"

for i in `seq 1 6`; do
    rlPhaseStartTest "Test ${C_NAME[$i]} cipher with OpenSSL server"
        rlRun "(echo server hello; sleep 2) | openssl s_server -key openssl-certs/ec_server_key.key -cert openssl-certs/ec_server_cert.pem -cipher ${C_NAME[$i]} > server.log 2> server.err &" 0 "Run server"
        server_pid=$!
        rlRun "kill -s 0 $server_pid" 0 "Check if server is running in background"
        rlRun "$NSS_CLIENT -h localhost -p 4433 -d certdb -V 'ssl3:' -c ':${C_HEXID[$i]}' < client.in > client.log 2> client.err"
        rlRun "kill -s 15 $server_pid" 1 "Kill the server in case the test fails"
        rlRun "wait $server_pid" 0 "Wait for server to be killed"
        rlAssertGrep "client hello" server.log
        rlAssertGrep "server hello" client.log
        rlRun "grep -iE 'fail|error' server.log && grep -iE 'fail|error' server.err" 1 "Check if there are no errors in server output"
        rlRun "grep -iE 'fail|error' client.log && grep -iE 'fail|error' client.log" 1 "Check if there are no errors in client output"
        echo "============= server.log follows ================"
        cat server.log
        echo "============= server.err follows ================"
        cat server.err
        echo "============= client.log follows ================"
        cat client.log
        echo "============= client.err follows ================"
        cat client.err
    rlPhaseEnd
done

C_NAME[1]="ECDHE-RSA-AES256-GCM-SHA384"
C_HEXID[1]="C030"
C_NAME[2]="ECDHE-RSA-AES256-SHA384"
C_HEXID[2]="C028"
C_NAME[3]="ECDHE-RSA-AES256-SHA"
C_HEXID[3]="C014"
C_NAME[4]="DHE-RSA-AES256-GCM-SHA384"
C_HEXID[4]="009F"
C_NAME[5]="DHE-RSA-AES256-SHA256"
C_HEXID[5]="006B"
C_NAME[6]="DHE-RSA-AES256-SHA"
C_HEXID[6]="0039"
C_NAME[7]="AES256-GCM-SHA384"
C_HEXID[7]="009D"
C_NAME[8]="AES256-SHA256"
C_HEXID[8]="003D"
C_NAME[9]="AES256-SHA"
C_HEXID[9]="0035"
C_NAME[10]="ECDHE-RSA-AES128-GCM-SHA256"
C_HEXID[10]="C02F"
C_NAME[11]="ECDHE-RSA-AES128-SHA256"
C_HEXID[11]="C027"
C_NAME[12]="AES128-GCM-SHA256"
C_HEXID[12]="009C"

for i in `seq 1 12`; do
    rlPhaseStartTest "Test ${C_NAME[$i]} cipher with OpenSSL server"
        rlRun "(echo server hello; sleep 2) | openssl s_server -key openssl-certs/rsa_server_key.key -cert openssl-certs/rsa_server_cert.pem -cipher ${C_NAME[$i]} > server.log 2> server.err &" 0 "Run server"
        server_pid=$!
        rlRun "kill -s 0 $server_pid" 0 "Check if server is running in background"
        rlRun "$NSS_CLIENT -h localhost -p 4433 -d certdb -V 'ssl3:' -c ':${C_HEXID[$i]}' < client.in > client.log 2> client.err"
        rlRun "kill -s 15 $server_pid" 1 "Kill the server in case the test fails"
        rlRun "wait $server_pid" 0 "Wait for server to be killed"
        rlAssertGrep "client hello" server.log
        rlAssertGrep "server hello" client.log
        rlRun "grep -iE 'fail|error' server.log && grep -iE 'fail|error' server.err" 1 "Check if there are no errors in server output"
        rlRun "grep -iE 'fail|error' client.log && grep -iE 'fail|error' client.log" 1 "Check if there are no errors in client output"
        echo "============= server.log follows ================"
        cat server.log
        echo "============= server.err follows ================"
        cat server.err
        echo "============= client.log follows ================"
        cat client.log
        echo "============= client.err follows ================"
        cat client.err
    rlPhaseEnd
done

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
