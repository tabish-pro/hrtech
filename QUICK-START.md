# Quick Start Guide - HTTPS Deployment

This is a condensed deployment guide for production HTTPS setup with self-signed certificates.

## Prerequisites

✅ Linux server with Docker installed
✅ Domain name pointing to server (e.g., `cvanalyzer.lamprell.com`)
✅ OpenRouter API key
✅ Firewall allows outbound HTTPS (443) and inbound ports 80, 443

## Deploy in 3 Steps

### 1. Configure Environment

```bash
cd ~/hrtech
cp .env.example .env
nano .env
```

Set these required values:
```bash
OPENROUTER_API_KEY=sk-or-your-key-here
DOMAIN_NAME=cvanalyzer.lamprell.com
DEFAULT_ADMIN_PASSWORD=your_secure_password
```

### 2. Build and Start

```bash
sudo docker compose build
sudo docker compose up -d
```

### 3. Verify

```bash
# Check all services running
sudo docker compose ps

# Test HTTPS (self-signed cert warning is normal)
curl -k https://cvanalyzer.lamprell.com
```

## Access the Application

1. Open browser: `https://cvanalyzer.lamprell.com`
2. Accept self-signed certificate warning (one-time per device)
3. Login with: `hradmin` / `your_secure_password`

## What Just Happened?

✅ Nginx generated a self-signed SSL certificate (valid 10 years)
✅ HTTP (port 80) redirects to HTTPS (port 443)
✅ Node.js app running on internal port 3000
✅ PostgreSQL database initialized
✅ Admin account created

## Firewall Requirements

**Inbound** (local network):
- Port 80 (HTTP redirect)
- Port 443 (HTTPS)

**Outbound** (HTTPS only):
- Docker Hub: `registry-1.docker.io`
- OpenRouter: `openrouter.ai`
- SendGrid: `api.sendgrid.com` (if using email)
- npm: `registry.npmjs.org`

## Common Commands

```bash
# View logs
sudo docker compose logs -f

# Restart services
sudo docker compose restart

# Stop everything
sudo docker compose down

# Rebuild after changes
sudo docker compose down
sudo docker compose build
sudo docker compose up -d
```

## Troubleshooting

### Certificate Warning Won't Go Away
This is expected with self-signed certificates. Users must accept the warning on each new device/browser.

### Can't Connect
```bash
# Check if nginx is running
sudo docker compose ps nginx

# View nginx logs
sudo docker compose logs nginx

# Check ports are listening
ss -tulpn | grep -E ':(80|443)'
```

### 502 Bad Gateway
```bash
# Restart app
sudo docker compose restart app

# Check app logs
sudo docker compose logs app
```

## Next Steps

- Configure SendGrid for email reports (optional)
- Set up database backups
- Review [DEPLOYMENT-HTTPS.md](DEPLOYMENT-HTTPS.md) for detailed guide
- Check [FirewallWhitelist.md](FirewallWhitelist.md) for complete firewall rules

## Production Checklist

- [ ] Strong admin password set
- [ ] Firewall configured
- [ ] All services running
- [ ] HTTPS accessible
- [ ] Certificate accepted in browsers
- [ ] Login works
- [ ] Resume analysis tested

Your application is now ready for use!
