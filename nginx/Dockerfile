FROM nginx:alpine

# Install openssl for self-signed certificate generation
RUN apk add --no-cache openssl

# Create directories for certificates and logs
RUN mkdir -p /etc/nginx/ssl /var/log/nginx

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy certificate generation script
COPY generate-ssl-cert.sh /usr/local/bin/generate-ssl-cert.sh
RUN chmod +x /usr/local/bin/generate-ssl-cert.sh

# Generate self-signed certificate on container startup
RUN /usr/local/bin/generate-ssl-cert.sh

# Expose HTTP and HTTPS ports
EXPOSE 80 443

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
