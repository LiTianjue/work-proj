#!/bin/bash
# $1 key
# $2 cert
# $3 out pfx

openssl pkcs12 -nodes -export -inkey $1 -in $2 -out $3 -passout pass:$4
