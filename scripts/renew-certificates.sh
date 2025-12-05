#!/bin/bash

set -e

LOG_FILE="/var/log/certbot-renew.log"

echo "=========================================" >> $LOG_FILE
echo "Certificate Renewal Check: $(date)" >> $LOG_FILE
echo "=========================================" >> $LOG_FILE

# Attempt renewal (only renews if <30 days until expiry)
certbot renew --webroot --webroot-path=/var/www/certbot >> $LOG_FILE 2>&1

if [ $? -eq 0 ]; then
    echo "Certificate check completed" >> $LOG_FILE
    nginx -s reload >> $LOG_FILE 2>&1
    echo "Nginx reloaded" >> $LOG_FILE
else
    echo "ERROR: Certificate renewal failed" >> $LOG_FILE
fi

echo "=========================================" >> $LOG_FILE
