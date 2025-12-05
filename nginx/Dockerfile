FROM nginx:alpine

# Note: OpenSSL is already included in nginx:alpine base image
# No need to install additional packages - avoids Alpine repo access

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

# Start nginx via startup script (generates cert first, then starts nginx)
CMD ["/usr/local/bin/start-nginx.sh"]
