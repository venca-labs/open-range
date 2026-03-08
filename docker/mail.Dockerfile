FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    postfix \
    dovecot-core \
    dovecot-imapd \
    openssh-server \
    rsyslog \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# Basic Postfix configuration
RUN postconf -e 'myhostname = mail.meridianhealth.local' && \
    postconf -e 'mydomain = meridianhealth.local' && \
    postconf -e 'mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain' && \
    postconf -e 'inet_interfaces = all' && \
    postconf -e 'inet_protocols = ipv4' && \
    postconf -e 'mailbox_size_limit = 51200000' && \
    postconf -e 'message_size_limit = 10240000'

# Create mail directories
RUN mkdir -p /var/mail/vhosts/meridianhealth.local && \
    mkdir -p /var/log/mail

EXPOSE 25 143 22

COPY mail-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
