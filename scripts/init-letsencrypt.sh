#!/bin/bash

set -e

echo "========================================="
echo "Let's Encrypt Certificate Setup"
echo "========================================="

# Check .env file
if [ ! -f .env ]; then
    echo "ERROR: .env file not found"
    exit 1
fi

source .env

# Validate required variables
if [ -z "$DOMAIN_NAME" ]; then
    echo "ERROR: DOMAIN_NAME not set in .env file"
    exit 1
fi

if [ -z "$SSL_EMAIL" ]; then
    echo "ERROR: SSL_EMAIL not set in .env file"
    exit 1
fi

# Staging vs production
STAGING_FLAG=""
if [ "${STAGING:-0}" = "1" ]; then
    echo "Using Let's Encrypt STAGING environment"
    STAGING_FLAG="--staging"
else
    echo "Using Let's Encrypt PRODUCTION environment"
fi

echo "Domain: $DOMAIN_NAME"
echo "Email: $SSL_EMAIL"
echo "========================================="

# Start services
echo "Starting Docker services..."
docker-compose up -d
sleep 30

# Test HTTP connectivity
echo "Testing HTTP connectivity..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN_NAME 2>/dev/null || echo "000")
if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "302" ] && [ "$HTTP_CODE" != "301" ]; then
    echo "WARNING: HTTP test returned code $HTTP_CODE"
    echo "Ensure DNS points to this server and port 80 is open"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Create ACME challenge directory
echo "Creating ACME challenge directory..."
mkdir -p nginx/certbot-webroot/.well-known/acme-challenge

# Generate certificate
echo "Requesting SSL certificate..."
docker-compose exec -T nginx certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email $SSL_EMAIL \
    --agree-tos \
    --no-eff-email \
    $STAGING_FLAG \
    -d $DOMAIN_NAME \
    --non-interactive

if [ $? -ne 0 ]; then
    echo "ERROR: Certificate generation failed!"
    exit 1
fi

# Verify certificate
echo "Verifying certificate..."
if docker-compose exec -T nginx test -f /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem; then
    echo "SUCCESS: Certificate generated!"
else
    echo "ERROR: Certificate not found!"
    exit 1
fi

# Update SSL config with domain name
echo "Updating SSL configuration..."
docker-compose exec -T nginx sed -i "s/\${DOMAIN_NAME}/$DOMAIN_NAME/g" /etc/nginx/nginx-ssl.conf

# Switch to SSL configuration
echo "Switching to SSL configuration..."
docker-compose exec -T nginx cp /etc/nginx/nginx-ssl.conf /etc/nginx/nginx.conf

# Test configuration
echo "Testing Nginx configuration..."
docker-compose exec -T nginx nginx -t

if [ $? -ne 0 ]; then
    echo "ERROR: Nginx configuration test failed!"
    exit 1
fi

# Reload Nginx
echo "Reloading Nginx..."
docker-compose exec -T nginx nginx -s reload

# Test HTTPS
echo "Testing HTTPS connectivity..."
sleep 5
HTTPS_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" https://$DOMAIN_NAME 2>/dev/null || echo "000")
if [ "$HTTPS_CODE" = "200" ] || [ "$HTTPS_CODE" = "302" ] || [ "$HTTPS_CODE" = "301" ]; then
    echo "SUCCESS: HTTPS is working!"
else
    echo "WARNING: HTTPS test returned code $HTTPS_CODE"
fi

echo "========================================="
echo "SSL Setup Complete!"
echo "========================================="
echo "Your application: https://$DOMAIN_NAME"
echo "Certificate auto-renewal configured"
echo "========================================="

if [ "${STAGING:-0}" = "1" ]; then
    echo ""
    echo "NOTE: Using STAGING certificates!"
    echo "To switch to production:"
    echo "  1. Set STAGING=0 in .env"
    echo "  2. Run: docker-compose exec nginx rm -rf /etc/letsencrypt/live"
    echo "  3. Run: ./scripts/init-letsencrypt.sh"
fi
