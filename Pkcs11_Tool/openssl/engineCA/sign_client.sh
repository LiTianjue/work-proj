#~/bin/bash

# $1 client.csr
# $2 ca.crt
# $3 CA key id
# $4 client.crt
#

openssl x509 -sha1 -req -in $1 -CA $2 -CAkey label_$2 -CAkeyform engine  -out $4 -CAcreateserial  -days 365 -engine pkcs11
