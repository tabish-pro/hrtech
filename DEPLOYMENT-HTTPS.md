# HTTPS Deployment Guide - Self-Signed Certificate

This guide explains how to deploy the HR Tech Resume Analyzer with HTTPS using self-signed certificates.

## Overview

The application is configured to use:
- **Nginx reverse proxy** for SSL termination
- **Self-signed SSL certificates** (valid for 10 years)
- **Automatic HTTP to HTTPS redirect**
- **No external dependencies** - works in highly firewalled environments

## What is a Self-Signed Certificate?

A self-signed certificate provides encryption (HTTPS) but is not verified by a trusted Certificate Authority (CA). This means:

**Pros:**
- Full encryption of data in transit
- No internet connectivity required
- Works immediately with IP addresses or domains
- Free and no expiration concerns (10-year validity)
- Perfect for internal/corporate applications

**Cons:**
- Browsers show a security warning on first visit
- Users must manually accept the certificate
- Not recommended for public-facing consumer applications

## Prerequisites

- Docker and Docker Compose installed
- Ports 80 and 443 open in firewall (inbound)
- `.env` file configured (optional: set DOMAIN_NAME)

## Deployment Steps

### 1. Configure Environment

Edit the `.env` file:

```bash
# Optional - used in certificate generation
DOMAIN_NAME=cvanalyzer.lamprell.com  # Or your domain/IP
```

If you omit `DOMAIN_NAME`, it defaults to `localhost`.

### 2. Build and Start Services

```bash
# Stop any existing services
docker-compose down

# Build with new configuration
docker-compose build

# Start all services
docker-compose up -d
```

The Nginx container will automatically:
- Generate a self-signed SSL certificate
- Configure HTTPS on port 443
- Set up HTTP to HTTPS redirect on port 80

### 3. Verify Deployment

**Check service status:**
```bash
docker-compose ps
```

All three services should be running:
- `hrtech-app-1` (Node.js application)
- `hrtech-db-1` (PostgreSQL database)
- `hrtech-nginx-1` (Nginx reverse proxy)

**View logs:**
```bash
docker-compose logs nginx
```

You should see:
```
Generating self-signed SSL certificate...
Self-signed SSL certificate generated successfully!
```

**Test HTTP redirect:**
```bash
curl -I http://your-server-ip-or-domain
```

Should return: `301 Moved Permanently` with `Location: https://...`

**Test HTTPS access:**
```bash
curl -k https://your-server-ip-or-domain
```

The `-k` flag ignores the self-signed certificate warning.

### 4. Access the Application

Open a web browser and navigate to:
```
https://cvanalyzer.lamprell.com
```
or
```
https://your-server-ip
```

## Accepting the Self-Signed Certificate

When you first visit the site, the browser will show a security warning:

### Chrome/Edge:
1. Click "Advanced"
2. Click "Proceed to [site] (unsafe)"
3. The site will load and work normally

### Firefox:
1. Click "Advanced"
2. Click "Accept the Risk and Continue"
3. The site will load and work normally

### Safari:
1. Click "Show Details"
2. Click "visit this website"
3. Confirm you want to visit the website

**Note:** This warning appears because the certificate is self-signed. The connection is still encrypted - browsers just can't verify the certificate's authenticity.

## Firewall Requirements

### Minimal Firewall Rules

**Inbound:**
- TCP 80 (HTTP - for redirects)
- TCP 443 (HTTPS - for the application)

**Outbound:**
- TCP 443 to Docker Hub (`https://registry-1.docker.io`, `https://auth.docker.io`)
- TCP 443 to OpenRouter API (`https://openrouter.ai`)
- TCP 443 to SendGrid API (`https://api.sendgrid.com`)
- TCP 443/80 to Alpine Linux repos (`https://dl-cdn.alpinelinux.org`) - only during build

**No longer required:**
- ~~Let's Encrypt ACME servers~~
- ~~OCSP responders~~
- ~~Alpine mirrors (after initial build)~~

## Architecture

```
Internet
    |
    v
Firewall (ports 80, 443)
    |
    v
Nginx Container (SSL termination)
    |
    v
Node.js App Container (port 3000, internal)
    |
    v
PostgreSQL Container (port 5432, internal)
```

## Troubleshooting

### Issue: Certificate Warning Won't Go Away

This is expected with self-signed certificates. Users must accept the warning each time they visit from a new device/browser.

**Solution:** Add the certificate to the device's trusted certificate store, or switch to a CA-signed certificate.

### Issue: "Connection Refused" on Port 443

**Check:**
```bash
# Verify nginx is running
docker-compose ps nginx

# Check nginx logs
docker-compose logs nginx

# Verify port binding
netstat -tulpn | grep 443
```

**Fix:**
```bash
docker-compose restart nginx
```

### Issue: HTTP Doesn't Redirect to HTTPS

**Check nginx configuration:**
```bash
docker-compose exec nginx nginx -t
```

**Reload nginx:**
```bash
docker-compose exec nginx nginx -s reload
```

### Issue: "502 Bad Gateway"

This means Nginx can't reach the Node.js app.

**Check:**
```bash
# Verify app is running
docker-compose ps app

# Check app logs
docker-compose logs app

# Test internal connectivity
docker-compose exec nginx wget -O- http://app:3000
```

**Fix:**
```bash
docker-compose restart app
```

## Upgrading to a Real Certificate (Future)

If you later want to use a trusted certificate (no browser warnings), you have options:

### Option 1: Let's Encrypt (Requires Internet Access)

You'll need firewall access to:
- `https://acme-v02.api.letsencrypt.org`
- Alpine Linux package repositories

The original Let's Encrypt setup is documented separately.

### Option 2: Purchase a Certificate

1. Buy a certificate from a CA (Digicert, Sectigo, etc.)
2. Place certificate files in the container
3. Update nginx.conf to point to the new certificate paths
4. Rebuild and restart

### Option 3: Use Cloudflare Tunnel

Cloudflare provides free SSL certificates via their tunnel service:
- Only requires outbound access to `https://api.cloudflare.com`
- No inbound ports needed
- Automatic certificate management

## Security Considerations

### Encryption

Even with a self-signed certificate, all traffic is encrypted with:
- TLS 1.2 and 1.3
- Strong cipher suites (ECDHE, AES-GCM, ChaCha20)
- Perfect Forward Secrecy

### Security Headers

The following security headers are enabled:
- `Strict-Transport-Security` (HSTS)
- `X-Frame-Options` (clickjacking protection)
- `X-Content-Type-Options` (MIME sniffing protection)
- `X-XSS-Protection` (XSS filtering)
- `Referrer-Policy`

### Certificate Validity

The self-signed certificate is valid for **10 years**. After 10 years:

1. Rebuild the nginx container to generate a new certificate:
   ```bash
   docker-compose build nginx
   docker-compose up -d nginx
   ```

2. Or manually generate a new certificate:
   ```bash
   docker-compose exec nginx /usr/local/bin/generate-ssl-cert.sh
   docker-compose restart nginx
   ```

## Monitoring

### Check Certificate Expiry

```bash
echo | openssl s_client -connect your-server:443 2>/dev/null | openssl x509 -noout -dates
```

### View Certificate Details

```bash
echo | openssl s_client -connect your-server:443 2>/dev/null | openssl x509 -noout -text
```

### Monitor Nginx Logs

```bash
# Real-time logs
docker-compose logs -f nginx

# Access logs
docker-compose exec nginx tail -f /var/log/nginx/access.log

# Error logs
docker-compose exec nginx tail -f /var/log/nginx/error.log
```

## Maintenance

### Restart Services

```bash
# Restart all services
docker-compose restart

# Restart only nginx
docker-compose restart nginx

# Restart only app
docker-compose restart app
```

### Update Configuration

If you modify `nginx.conf`:

```bash
# Test configuration
docker-compose exec nginx nginx -t

# Reload without downtime
docker-compose exec nginx nginx -s reload
```

### Regenerate Certificate

```bash
# Remove old certificate
docker-compose exec nginx rm /etc/nginx/ssl/cert.pem /etc/nginx/ssl/key.pem

# Generate new certificate
docker-compose exec nginx /usr/local/bin/generate-ssl-cert.sh

# Reload nginx
docker-compose exec nginx nginx -s reload
```

## Summary

Your application is now running with HTTPS using a self-signed certificate:

- **URL:** `https://cvanalyzer.lamprell.com` (or your configured domain/IP)
- **Encryption:** Full TLS 1.2/1.3 encryption
- **Firewall:** Minimal requirements (ports 80, 443)
- **Maintenance:** Zero - certificate valid for 10 years
- **User Experience:** One-time browser warning, then normal

This setup is ideal for:
- Internal corporate applications
- Highly firewalled environments
- Development and testing
- Applications where users can be instructed to accept the certificate

For public-facing applications, consider upgrading to Let's Encrypt or a purchased certificate in the future.
