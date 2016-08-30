#!/bin/bash

# if ecc key
openssl ec -in $1 -inform PEM -out $2 -outform DER


# if rsa key
openssl rsa -in $1 -inform PEM -out $2 -outform DER
