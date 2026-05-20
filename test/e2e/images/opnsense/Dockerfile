FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iproute2 iptables nftables tcpdump iputils
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
