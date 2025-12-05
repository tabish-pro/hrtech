# Firewall Whitelist — Lamprell Resume Analyzer

Notes:
- Allow HTTPS (TCP 443) to all listed hosts. Some OS package repos use HTTP/HTTPS; prefer HTTPS.
- Where apt repos are used, allow Ubuntu archive and security hosts for system updates.
- Container pulls (Docker) use Docker Hub registry endpoints (registry-1.docker.io / auth.docker.io).
- Node/npm package installs require access to npm registries and GitHub for some packages.
- AI/email API endpoints are required at runtime by the server (`OPENROUTER_API_KEY`, `SENDGRID_API_KEY`).

Core runtime / API services
- https://openrouter.ai
- https://openrouter.ai/api/v1
  - Notes: Used by server code via [`makeOpenRouterRequest()`](server.js) and [`queryAvailableModels()`](server.js). See [`OPENROUTER_API_KEY`](server.js).

- https://api.sendgrid.com
- https://sendgrid.com
  - Notes: Used for email sending (server expects `SENDGRID_API_KEY`) and SendGrid API calls (POST /v3/mail/send).

Package registries & build tooling
- https://registry.npmjs.org
- https://npmjs.com
- https://registry.yarnpkg.com (optional)
- https://nodejs.org
- https://deb.nodesource.com (if installing Node.js via NodeSource)
  - Notes: For `npm install`, Node runtime and many JS dependencies (e.g., `mammoth`, `openai` package).

Container images & registries
- https://registry-1.docker.io
- https://auth.docker.io
- https://hub.docker.com
- https://download.docker.com
- https://get.docker.com
  - Notes: Pulling official images (e.g., `postgres:13-alpine`, `nginx:alpine` from docker-compose), installing Docker Engine.

Alpine Linux package repositories (for nginx:alpine and postgres:13-alpine containers)
- https://dl-cdn.alpinelinux.org
- http://dl-cdn.alpinelinux.org
- https://alpine.global.ssl.fastly.net
- http://alpine.global.ssl.fastly.net
- https://mirrors.alpinelinux.org
  - Notes: Used by `apk` package manager inside Alpine-based Docker containers. Required for installing certbot, openssl, and other packages during container builds. Both HTTP and HTTPS may be used depending on Alpine mirror configuration.

Let's Encrypt / SSL Certificate services
- https://acme-v02.api.letsencrypt.org
- https://acme-staging-v02.api.letsencrypt.org
- https://letsencrypt.org
- https://r3.o.lencr.org
- https://r4.o.lencr.org
- https://r10.o.lencr.org
- https://r11.o.lencr.org
- https://e1.o.lencr.org
- https://e2.o.lencr.org
  - Notes: Used by Certbot for SSL certificate generation and renewal. Production API (acme-v02) for real certificates, staging API for testing. OCSP responders (r3, r4, r10, r11, e1, e2) used for certificate validation and OCSP stapling.

Git / source code hosting
- https://github.com
- https://api.github.com
- https://raw.githubusercontent.com
  - Notes: Cloning repo, fetching releases or raw files during builds.

Ubuntu / system package repos (required for apt / system updates)
- https://archive.ubuntu.com
- https://security.ubuntu.com
  - Notes: Base OS packages, apt updates, build deps when installing Docker/Node from apt.

Optional / common CDNs & tooling referenced in README/UI
- https://cdnjs.cloudflare.com (for Font Awesome / common libs if served from CDN)
- https://fonts.googleapis.com (if web fonts used)
  - Notes: May not be required if frontend bundles all assets, but whitelist if external CDNs are used.

Other useful endpoints (GPG/keys & misc)
- https://keyserver.ubuntu.com (if GPG key fetching is needed)
- https://packages.cloud.google.com (occasionally used by some build scripts; whitelist if required)

Database connectivity
- (Postgres runs locally or in Docker Compose; external DB URL if used:)
  - Allow the host specified by your `DATABASE_URL` (e.g., postgres server FQDN/IP + port 5432).
  - See [`DATABASE_URL`](server.js) and [docker-compose.yml](docker-compose.yml).

Ports
- Allow outbound TCP 443 (HTTPS) for all above hosts.
- Allow outbound TCP 80 (HTTP) for Alpine Linux mirrors and Let's Encrypt ACME challenges.
- Allow inbound TCP 80 (HTTP) for Let's Encrypt ACME challenge verification and HTTP to HTTPS redirects.
- Allow inbound TCP 443 (HTTPS) for serving the application over SSL/TLS.
- If running PostgreSQL remotely, allow TCP 5432 to the DB host (only if external DB used).
- If exposing Docker daemon remotely (not recommended), allow TCP 2375/2376 as per your secure config.

Quick cross-check with workspace
- The server uses OpenRouter & SendGrid at runtime: see [`OPENROUTER_API_KEY`](server.js), [`SENDGRID_API_KEY`](server.js), and calls in [server.js](server.js).
- Docker images referenced in [docker-compose.yml](docker-compose.yml) will come from Docker Hub (registry-1.docker.io).
- Node packages are installed from npm registry: see [package.json](package.json).
- Frontend behavior and client-side uploads in [script.js](script.js) rely on the server APIs (no additional external endpoints required).


- Generate a minimal iptables/ufw allow script for these domains (requires resolving domain -> IPs; note CDNs and cloud providers have dynamic IPs).