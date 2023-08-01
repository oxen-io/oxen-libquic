#!/bin/bash

# Generates test certificates (servercert.pem, serverkey.pem, clientcert.pem, clientkey.pem) in the
# current working directory; these are the expected/default filenames for the test suite.
#
# Requires certtool (part of gnutls, found in the gnutls-bin package on Debian-like systems).

set -e

bin=certtool
if [ "$(uname -s)" == Darwin ]; then
    bin=gnutls-certtool
fi

if ! type -p $bin && [ -x ./static-deps/bin/certtool ]; then
    bin=./static-deps/bin/certtool
fi

for f in server client; do
    $bin -p --key-type ${KEY_TYPE:-ed448} --outfile ${f}key.pem --no-text
    $bin -s --load-privkey ${f}key.pem --no-text --template <(echo 'expiration_days=-1') --outfile=${f}cert.pem
done
