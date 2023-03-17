if [ -z $1 ]; then
    echo "run with path to certs <./renew.sh /path/to/wolfssl/certs>"
    exit 1
fi

CERTS_DIR=$1

echo "Copy over test keys"
cp  $CERTS_DIR/client-key.pem .
cp  $CERTS_DIR/ecc-client-key.pem .

echo "Copy over test certificates"
cp  $CERTS_DIR/client-cert.pem .
cp  $CERTS_DIR/client-ecc-cert.pem .
