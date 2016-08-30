#!/bin/bash
#openssl req -new -x509 -days 365 -key 01 -keyform engine -out ca.crt -config ./openssl.conf -engine pkcs11

# $1 key label : RSA_PRIVATE_KEY_01

openssl req -new -x509 -days 365 -key label_$1 -keyform engine -out ca.crt -config ./openssl.conf -engine pkcs11
