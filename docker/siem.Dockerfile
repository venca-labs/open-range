FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    rsyslog \
    rsyslog-relp \
    openssh-server \
    curl \
    jq \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# Configure rsyslog to accept remote logs
RUN mkdir -p /var/log/siem/consolidated && \
    echo 'module(load="imtcp")' > /etc/rsyslog.d/50-remote.conf && \
    echo 'input(type="imtcp" port="514")' >> /etc/rsyslog.d/50-remote.conf && \
    echo 'module(load="imudp")' >> /etc/rsyslog.d/50-remote.conf && \
    echo 'input(type="imudp" port="514")' >> /etc/rsyslog.d/50-remote.conf && \
    echo '*.* /var/log/siem/consolidated/all.log' >> /etc/rsyslog.d/50-remote.conf

EXPOSE 514/tcp 514/udp 22

COPY siem-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
