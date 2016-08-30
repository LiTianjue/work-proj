#!/bin/bash
openssl x509 -in $1 -inform PEM -out $2 -outform DER
