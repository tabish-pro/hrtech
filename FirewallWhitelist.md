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

Alpine Linux package repositories (for postgres:13-alpine container only)
- https://dl-cdn.alpinelinux.org
- http://dl-cdn.alpinelinux.org
  - Notes: Used by `apk` package manager in PostgreSQL Alpine container during initial build. Nginx uses Debian base image (nginx:latest) which does NOT require Alpine repos.

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

Ports (Production HTTPS Setup)
- **Inbound (Local Network Only)**:
  - TCP 80 (HTTP) - HTTP to HTTPS redirect
  - TCP 443 (HTTPS) - Application access with self-signed SSL
- **Outbound**:
  - TCP 443 (HTTPS) - Docker Hub, OpenRouter API, SendGrid API, npm registry
  - TCP 80 (HTTP) - Alpine repos during PostgreSQL container build (one-time)
- **Not Required**:
  - ~~Port 3000 (blocked - internal only)~~
  - ~~Port 5432 (PostgreSQL internal unless using external DB)~~

Quick cross-check with workspace
- The server uses OpenRouter & SendGrid at runtime: see [`OPENROUTER_API_KEY`](server.js), [`SENDGRID_API_KEY`](server.js), and calls in [server.js](server.js).
- Docker images referenced in [docker-compose.yml](docker-compose.yml) will come from Docker Hub (registry-1.docker.io).
- Node packages are installed from npm registry: see [package.json](package.json).
- Frontend behavior and client-side uploads in [script.js](script.js) rely on the server APIs (no additional external endpoints required).


- Generate a minimal iptables/ufw allow script for these domains (requires resolving domain -> IPs; note CDNs and cloud providers have dynamic IPs).