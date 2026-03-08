FROM alpine:3.19

RUN apk add --no-cache \
    iptables \
    ip6tables \
    iproute2 \
    tcpdump \
    bash \
    curl

# Default iptables rules -- Builder overlays specific rules per episode
COPY firewall-default.rules /etc/iptables/rules.v4

# Script to apply rules on startup
COPY firewall-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
