FROM nginx:alpine

# Install certbot for Let's Encrypt
RUN apk add --no-cache certbot

# Create directories
RUN mkdir -p /var/www/certbot /var/log

# Copy initial configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Expose HTTP and HTTPS ports
EXPOSE 80 443

# Add cron job for certificate renewal (runs daily at 3 AM)
RUN echo "0 3 * * * /usr/local/bin/renew-certificates.sh" > /etc/crontabs/root

# Start cron and nginx
CMD crond && nginx -g 'daemon off;'
