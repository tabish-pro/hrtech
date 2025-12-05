FROM nginx:latest

# Note: nginx:latest (Debian-based) includes OpenSSL by default
# Using Debian base instead of Alpine to avoid package manager during build

# Create directories for certificates and logs
RUN mkdir -p /etc/nginx/ssl /var/log/nginx

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy certificate generation script and startup script
COPY generate-ssl-cert.sh /usr/local/bin/generate-ssl-cert.sh
COPY start-nginx.sh /usr/local/bin/start-nginx.sh
RUN chmod +x /usr/local/bin/generate-ssl-cert.sh /usr/local/bin/start-nginx.sh

# Expose HTTP and HTTPS ports
EXPOSE 80 443

# Override the default entrypoint to use our startup script
ENTRYPOINT ["/usr/local/bin/start-nginx.sh"]
