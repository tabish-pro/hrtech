#!/bin/sh

# Generate self-signed SSL certificate for Nginx
# This script creates a certificate valid for 10 years

CERT_DIR="/etc/nginx/ssl"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

# Check if certificate already exists
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "SSL certificate already exists at $CERT_FILE"
    exit 0
fi

echo "Generating self-signed SSL certificate..."

# Generate private key and certificate
openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=IT/CN=${DOMAIN_NAME:-localhost}" \
    -addext "subjectAltName=DNS:${DOMAIN_NAME:-localhost},DNS:www.${DOMAIN_NAME:-localhost},IP:127.0.0.1"

# Set proper permissions
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "Self-signed SSL certificate generated successfully!"
echo "Certificate: $CERT_FILE"
echo "Private Key: $KEY_FILE"
echo "Valid for: 10 years"
echo ""
echo "NOTE: This is a self-signed certificate."
echo "Browsers will show a security warning that users must accept."
