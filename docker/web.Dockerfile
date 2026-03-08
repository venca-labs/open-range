FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    php-fpm \
    php-mysql \
    php-json \
    php-ldap \
    php-xml \
    php-mbstring \
    openssh-server \
    curl \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# Create default web root with a placeholder page
RUN mkdir -p /var/www/portal && \
    echo '<?php echo "Meridian Health Partners - Referral Portal"; ?>' > /var/www/portal/index.php

# Configure nginx to serve PHP
COPY web-nginx-default.conf /etc/nginx/sites-available/default

# Logging: symlink nginx logs to shared volume path
RUN mkdir -p /var/log/app && \
    ln -sf /var/log/app/access.log /var/log/nginx/access.log && \
    ln -sf /var/log/app/error.log /var/log/nginx/error.log

EXPOSE 80 443 22

COPY web-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
