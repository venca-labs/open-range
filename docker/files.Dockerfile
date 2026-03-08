FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    samba \
    samba-common \
    smbclient \
    openssh-server \
    rsyslog \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# Create departmental share directories
RUN mkdir -p /srv/shares/contracts \
             /srv/shares/hr \
             /srv/shares/compliance \
             /srv/shares/general && \
    chmod -R 0770 /srv/shares

# Basic Samba configuration
COPY samba-smb.conf /etc/samba/smb.conf

# Create log directory
RUN mkdir -p /var/log/samba

EXPOSE 445 139 22

COPY files-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
