#!/bin/bash

# $1 output pfx
# $2 clien.key
# $3 cleint.crt
# $4 ca.crt
#

# with CA
#openssl pkcs12 -export -out $1 -inkey $2 -in $3 -certfile $4

# without CA
openssl pkcs12 -nodes -export -out $1 -inkey $2 -in $3 -passout pass:$4

