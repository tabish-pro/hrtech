#!/bin/sh

# Startup script for Nginx with self-signed certificate generation

echo "Starting Nginx with HTTPS support..."

# Generate self-signed certificate if it doesn't exist
if [ ! -f /etc/nginx/ssl/cert.pem ] || [ ! -f /etc/nginx/ssl/key.pem ]; then
    echo "Certificate not found. Generating self-signed certificate..."
    /usr/local/bin/generate-ssl-cert.sh
else
    echo "Certificate already exists. Skipping generation."
fi

# Start nginx in foreground
echo "Starting Nginx..."
exec nginx -g 'daemon off;'
