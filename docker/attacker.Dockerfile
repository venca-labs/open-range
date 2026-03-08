FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Install common offensive security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sqlmap \
    hydra \
    smbclient \
    nikto \
    curl \
    wget \
    openssh-client \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    whois \
    tcpdump \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Create workspace for Red team operations
RUN mkdir -p /opt/red-team/loot /opt/red-team/scripts /opt/red-team/notes

WORKDIR /opt/red-team

CMD ["bash"]
