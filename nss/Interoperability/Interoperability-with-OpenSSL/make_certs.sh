#!/bin/bash

lsb_release -r | grep -E '\<5[.]' && FORMAT="+%y%m%d%H%M%SZ" || FORMAT="+%Y%m%d%H%M%SZ" 

set -e

_DIR="openssl-certs"
_RSA_CA_CNF_FILE="${_DIR}/ca.cnf"
_EC_CA_CNF_FILE="${_DIR}/ca2.cnf"
_RSAEC_SERVER_CNF_FILE="${_DIR}/rsaec-server.cnf"
_RSA_SERVER_CNF_FILE="${_DIR}/rsa-server.cnf"
_EC_SERVER_CNF_FILE="${_DIR}/ec-server.cnf"
_INDEX_FILE="${_DIR}/rsa-index.txt"
_INDEX2_FILE="${_DIR}/ec-index.txt"
_SERIAL_FILE="${_DIR}/rsa-serial"
_SERIAL2_FILE="${_DIR}/ec-serial"
_RAND_FILE="${_DIR}/rand"
_COUNTRY="CZ"
_STATE="Czech Republic"
_CITY="Brno"
_ORG_NAME="TestRedHat"
_RSA_CA_COMMON_NAME="CA"
_RSA_CA_KEY_FILE="${_DIR}/ca_key.pem"
_RSA_CA_BINARY_KEY_FILE="${_DIR}/ca_key.key"
_RSA_CA_CERT_FILE="${_DIR}/ca_cert.pem"
_RSA_CA_CRL_FILE="${_DIR}/ca_cert.crl"
_RSA_CA_PASSWORD="RedHatEnterpriseLinux"
_RSA_CA_EMAIL="ca@test-redhat.example.com"
_EC_CA_COMMON_NAME="CA2"
_EC_CA_KEY_FILE="${_DIR}/ca2_key.pem"
_EC_CA_BINARY_KEY_FILE="${_DIR}/ca2_key.key"
_EC_CA_CERT_FILE="${_DIR}/ca2_cert.pem"
_EC_CA_CRL_FILE="${_DIR}/ca2_cert.crl"
_EC_CA_PASSWORD="RedHatEnterpriseLinux"
_EC_CA_EMAIL="ca@test-redhat.example.com"
_RSA_SERVER_COMMON_NAME="localhost"
_RSA_SERVER_KEY_FILE="${_DIR}/rsa_server_key.pem"
_RSA_SERVER_BINARY_KEY_FILE="${_DIR}/rsa_server_key.key"
_RSA_SERVER_CERT_FILE="${_DIR}/rsa_server_cert.pem"
_RSA_SERVER_REQUEST_FILE="${_DIR}/rsa_server_cert.csr"
_RSA_SERVER_P12_FILE="${_DIR}/rsa_server.p12"
_RSA_SERVER_KEYCERT_FILE="${_DIR}/rsa_server.pem"
_RSA_SERVER_PASSWORD="${_RSA_CA_PASSWORD}"
_RSA_SERVER_EMAIL="server@test-redhat.example.com"
_EC_SERVER_COMMON_NAME="localhost"
_EC_SERVER_KEY_FILE="${_DIR}/ec_server_key.pem"
_EC_SERVER_BINARY_KEY_FILE="${_DIR}/ec_server_key.key"
_EC_SERVER_CERT_FILE="${_DIR}/ec_server_cert.pem"
_EC_SERVER_REQUEST_FILE="${_DIR}/ec_server_cert.csr"
_EC_SERVER_P12_FILE="${_DIR}/ec_server.p12"
_EC_SERVER_KEYCERT_FILE="${_DIR}/ec_server.pem"
_EC_SERVER_PASSWORD="${_EC_CA_PASSWORD}"
_EC_SERVER_EMAIL="server@test-redhat.example.com"
_RSAEC_SERVER_COMMON_NAME="RSA-EC-localhost"
_RSAEC_SERVER_KEY_FILE="${_DIR}/rsaec_server_key.pem"
_RSAEC_SERVER_BINARY_KEY_FILE="${_DIR}/rsaec_server_key.key"
_RSAEC_SERVER_CERT_FILE="${_DIR}/rsaec_server_cert.pem"
_RSAEC_SERVER_REQUEST_FILE="${_DIR}/rsaec_server_cert.csr"
_RSAEC_SERVER_P12_FILE="${_DIR}/rsaec_server.p12"
_RSAEC_SERVER_KEYCERT_FILE="${_DIR}/rsaec_server.pem"
_RSAEC_SERVER_PASSWORD="${_EC_CA_PASSWORD}"
_RSAEC_SERVER_EMAIL="server@test-redhat.example.com"
_ID="01"


function _config() {
	[ -d ${_DIR} ] && rm -rf ${_DIR}
	mkdir -p ${_DIR}/crl
    date_now=`date '+%s'`
    start_date=`date -d @"$(($date_now - 60*60*24* 365 * 5))" -u "$FORMAT"`
    end_date=`date -d @"$(($date_now + 60*60*24* 365 * 5))" -u "$FORMAT"`
	cat <<EOF >${_RSA_CA_CNF_FILE}
[ ca ]
default_ca		= CA_default

[ CA_default ]
dir			= ${_DIR}
certs			= ${_DIR}
crl_dir			= ${_DIR}/crl
database		= ${_INDEX_FILE}
new_certs_dir		= ${_DIR}
certificate		= ${_RSA_CA_CERT_FILE}
serial			= ${_SERIAL_FILE}
crl			= ${_RSA_CA_CRL_FILE}
private_key		= ${_RSA_CA_KEY_FILE}
RANDFILE		= ${_RAND_FILE}
name_opt		= ca_default
cert_opt		= ca_default
default_startdate = ${start_date}
default_enddate = ${end_date}
default_crl_days	= 30
default_md		= sha256
preserve		= no
policy			= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ req ]
prompt			= no
distinguished_name	= certificate_authority
default_bits		= 2048
input_password		= ${_RSA_CA_PASSWORD}
output_password		= ${_RSA_CA_PASSWORD}
x509_extensions		= v3_ca

[certificate_authority]
countryName		= ${_COUNTRY}
stateOrProvinceName	= ${_STATE}
localityName		= ${_CITY}
organizationName	= ${_ORG_NAME}
emailAddress		= ${_RSA_CA_EMAIL}
commonName		= "${_RSA_CA_COMMON_NAME}"

[v3_ca]
subjectKeyIdentifier	= hash
authorityKeyIdentifier	= keyid:always,issuer:always
basicConstraints	= CA:true
EOF

    start_date=`date -d @"$(($date_now - 60*60*24* 365 * 5))" -u "$FORMAT"`
    end_date=`date -d @"$(($date_now + 60*60*24* 365 * 5))" -u "$FORMAT"`
	cat <<EOF >${_EC_CA_CNF_FILE}
[ ca ]
default_ca		= CA_default

[ CA_default ]
dir			= ${_DIR}
certs			= ${_DIR}
crl_dir			= ${_DIR}/crl2
database		= ${_INDEX2_FILE}
new_certs_dir		= ${_DIR}
certificate		= ${_EC_CA_CERT_FILE}
serial			= ${_SERIAL2_FILE}
crl			= ${_EC_CA_CRL_FILE}
private_key		= ${_EC_CA_KEY_FILE}
RANDFILE		= ${_RAND_FILE}
name_opt		= ca_default
cert_opt		= ca_default
default_startdate = ${start_date}
default_enddate = ${end_date}
default_crl_days	= 30
default_md		= sha256
preserve		= no
policy			= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ req ]
prompt			= no
distinguished_name	= certificate_authority
default_bits		= 2048
input_password		= ${_EC_CA_PASSWORD}
output_password		= ${_EC_CA_PASSWORD}
x509_extensions		= v3_ca

[certificate_authority]
countryName		= ${_COUNTRY}
stateOrProvinceName	= ${_STATE}
localityName		= ${_CITY}
organizationName	= ${_ORG_NAME}
emailAddress		= ${_EC_CA_EMAIL}
commonName		= "${_EC_CA_COMMON_NAME}"

[v3_ca]
subjectKeyIdentifier	= hash
authorityKeyIdentifier	= keyid:always,issuer:always
basicConstraints	= CA:true
EOF

    start_date=`date -d @"$(($date_now - 60*60*24* 30 * 4))" -u "$FORMAT"`
    end_date=`date -d @"$(($date_now + 60*60*24* 40 * 8))" -u "$FORMAT"`
	cat <<EOF >${_RSA_SERVER_CNF_FILE}
[ ca ]
default_ca		= CA_default

[ CA_default ]
dir			= ${_DIR}
certs			= ${_DIR}
crl_dir			= ${_DIR}/crl
database		= ${_INDEX_FILE}
new_certs_dir		= ${_DIR}
certificate		= ${_RSA_SERVER_CERT_FILE}
serial			= ${_SERIAL_FILE}
crl			= ${_RSA_CA_CRL_FILE}
private_key		= ${_RSA_SERVER_KEY_FILE}
RANDFILE		= ${_RAND_FILE}
name_opt		= ca_default
cert_opt		= ca_default
default_startdate = ${start_date}
default_enddate = ${end_date}
default_crl_days	= 30
default_md		= sha256
preserve		= no
policy			= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ req ]
prompt			= no
distinguished_name	= client
default_bits		= 2048
input_password		= ${_RSA_SERVER_PASSWORD}
output_password		= ${_RSA_SERVER_PASSWORD}

[client]
countryName		= ${_COUNTRY}
stateOrProvinceName	= ${_STATE}
localityName		= ${_CITY}
organizationName	= ${_ORG_NAME}
emailAddress		= ${_RSA_SERVER_EMAIL}
commonName		= "${_RSA_SERVER_COMMON_NAME}"

[v3_ee]
basicConstraints =critical, CA:FALSE
keyUsage =critical, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
extendedKeyUsage=serverAuth
subjectAltName = @alt_name

[alt_name]
DNS.1=localhost
DNS.2=localhost4
DNS.3=localhost6

EOF

    start_date=`date -d @"$(($date_now - 60*60*24* 30 * 4))" -u "$FORMAT"`
    end_date=`date -d @"$(($date_now + 60*60*24* 40 * 8))" -u "$FORMAT"`
	cat <<EOF >${_EC_SERVER_CNF_FILE}
[ ca ]
default_ca		= CA_default

[ CA_default ]
dir			= ${_DIR}
certs			= ${_DIR}
crl_dir			= ${_DIR}/crl
database		= ${_INDEX2_FILE}
new_certs_dir		= ${_DIR}
certificate		= ${_EC_SERVER_CERT_FILE}
serial			= ${_SERIAL2_FILE}
crl			= ${_EC_CA_CRL_FILE}
private_key		= ${_EC_SERVER_KEY_FILE}
RANDFILE		= ${_RAND_FILE}
name_opt		= ca_default
cert_opt		= ca_default
default_startdate = ${start_date}
default_enddate = ${end_date}
default_crl_days	= 30
default_md		= sha256
preserve		= no
policy			= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ req ]
prompt			= no
distinguished_name	= client
default_bits		= 2048
input_password		= ${_EC_SERVER_PASSWORD}
output_password		= ${_EC_SERVER_PASSWORD}

[client]
countryName		= ${_COUNTRY}
stateOrProvinceName	= ${_STATE}
localityName		= ${_CITY}
organizationName	= ${_ORG_NAME}
emailAddress		= ${_EC_SERVER_EMAIL}
commonName		= "${_EC_SERVER_COMMON_NAME}"

[v3_ee]
basicConstraints =critical, CA:FALSE
keyUsage =critical, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
extendedKeyUsage=serverAuth
subjectAltName = @alt_name

[alt_name]
DNS.1=localhost
DNS.2=localhost4
DNS.3=localhost6

EOF

    start_date=`date -d @"$(($date_now - 60*60*24* 30 * 4))" -u "$FORMAT"`
    end_date=`date -d @"$(($date_now + 60*60*24* 40 * 8))" -u "$FORMAT"`
	cat <<EOF >${_RSAEC_SERVER_CNF_FILE}
[ ca ]
default_ca		= CA_default

[ CA_default ]
dir			= ${_DIR}
certs			= ${_DIR}
crl_dir			= ${_DIR}/crl
database		= ${_INDEX2_FILE}
new_certs_dir		= ${_DIR}
certificate		= ${_RSAEC_SERVER_CERT_FILE}
serial			= ${_SERIAL2_FILE}
crl			= ${_EC_CA_CRL_FILE}
private_key		= ${_RSAEC_SERVER_KEY_FILE}
RANDFILE		= ${_RAND_FILE}
name_opt		= ca_default
cert_opt		= ca_default
default_startdate = ${start_date}
default_enddate = ${end_date}
default_crl_days	= 30
default_md		= sha256
preserve		= no
policy			= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
subjectAltName  = optional

[ req ]
prompt			= no
distinguished_name	= client
default_bits		= 2048
input_password		= ${_RSAEC_SERVER_PASSWORD}
output_password		= ${_RSAEC_SERVER_PASSWORD}

[client]
countryName		= ${_COUNTRY}
stateOrProvinceName	= ${_STATE}
localityName		= ${_CITY}
organizationName	= ${_ORG_NAME}
emailAddress		= ${_RSAEC_SERVER_EMAIL}
commonName		= "${_RSAEC_SERVER_COMMON_NAME}"

[v3_ee]
basicConstraints =critical, CA:FALSE
keyUsage =critical, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
extendedKeyUsage=serverAuth
subjectAltName = @alt_name

[alt_name]
DNS.1=localhost
DNS.2=localhost4
DNS.3=localhost6

EOF

	echo "${_ID}" >${_SERIAL_FILE}
	touch ${_INDEX_FILE}
	echo "${_ID}" >${_SERIAL2_FILE}
	touch ${_INDEX2_FILE}
}


_config

openssl ecparam -out prime256v1 -name prime256v1

# RSA CA
openssl req -x509 -newkey rsa:2048 -keyout ${_RSA_CA_KEY_FILE} -out ${_RSA_CA_CERT_FILE} -extensions v3_ca -config ${_RSA_CA_CNF_FILE}
openssl rsa -in ${_RSA_CA_KEY_FILE} -out ${_RSA_CA_BINARY_KEY_FILE} -passin pass:${_RSA_CA_PASSWORD}

# EC CA2
openssl req -x509 -newkey ec:prime256v1 -keyout ${_EC_CA_KEY_FILE} -out ${_EC_CA_CERT_FILE} -extensions v3_ca -config ${_EC_CA_CNF_FILE}
openssl ec -in ${_EC_CA_KEY_FILE} -out ${_EC_CA_BINARY_KEY_FILE} -passin pass:${_EC_CA_PASSWORD}

# RSA server
openssl req -newkey rsa:2048 -keyout ${_RSA_SERVER_KEY_FILE} -out ${_RSA_SERVER_REQUEST_FILE} -config ${_RSA_SERVER_CNF_FILE}
openssl ca -batch -keyfile ${_RSA_CA_KEY_FILE} -cert ${_RSA_CA_CERT_FILE} -in ${_RSA_SERVER_REQUEST_FILE} -key ${_RSA_CA_PASSWORD} -out ${_RSA_SERVER_CERT_FILE} -extensions v3_ee -config ${_RSA_SERVER_CNF_FILE}
openssl rsa -in ${_RSA_SERVER_KEY_FILE} -out ${_RSA_SERVER_BINARY_KEY_FILE} -passin pass:${_RSA_SERVER_PASSWORD}

# RSA-EC server
openssl req -newkey ec:prime256v1 -keyout ${_RSAEC_SERVER_KEY_FILE} -out ${_RSAEC_SERVER_REQUEST_FILE} -config ${_RSAEC_SERVER_CNF_FILE}
openssl ca -batch -keyfile ${_RSA_CA_KEY_FILE} -cert ${_RSA_CA_CERT_FILE} -in ${_RSAEC_SERVER_REQUEST_FILE} -key ${_RSA_CA_PASSWORD} -out ${_RSAEC_SERVER_CERT_FILE} -extensions v3_ee -config ${_RSAEC_SERVER_CNF_FILE}
openssl ec -in ${_RSAEC_SERVER_KEY_FILE} -out ${_RSAEC_SERVER_BINARY_KEY_FILE} -passin pass:${_RSAEC_SERVER_PASSWORD}
openssl pkcs12 -export -in ${_RSAEC_SERVER_CERT_FILE} -inkey ${_RSAEC_SERVER_KEY_FILE} -out ${_RSAEC_SERVER_P12_FILE} -passin pass:${_RSAEC_SERVER_PASSWORD} -passout pass:${_RSAEC_SERVER_PASSWORD}
cat ${_RSAEC_SERVER_KEY_FILE} ${_RSAEC_SERVER_CERT_FILE} >${_RSAEC_SERVER_KEYCERT_FILE}
cp ${_RSAEC_SERVEREC_KEYCERT_FILE} ${_RSAEC_SERVER_P12_FILE} .

# EC server
openssl req -newkey ec:prime256v1 -keyout ${_EC_SERVER_KEY_FILE} -out ${_EC_SERVER_REQUEST_FILE} -config ${_RSA_SERVER_CNF_FILE}
openssl ca -batch -keyfile ${_EC_CA_KEY_FILE} -cert ${_EC_CA_CERT_FILE} -in ${_EC_SERVER_REQUEST_FILE} -key ${_EC_CA_PASSWORD} -out ${_EC_SERVER_CERT_FILE} -extensions v3_ee -config ${_EC_SERVER_CNF_FILE}
openssl ec -in ${_EC_SERVER_KEY_FILE} -out ${_EC_SERVER_BINARY_KEY_FILE} -passin pass:${_EC_SERVER_PASSWORD}

