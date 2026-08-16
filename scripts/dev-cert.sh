#!/usr/bin/env sh
set -eu

mkdir -p certs
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -days 365 \
  -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'

echo 'Generated certs/cert.pem and certs/key.pem'
