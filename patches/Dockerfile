# The exit server's image: the client and ethtool on the Alpine its boot script expects, so a machine downloads nothing
# at start. scripts/publish.sh builds and pushes it; the context holds the built client as `netbird`.
FROM alpine:3.24
RUN apk add --no-cache ethtool
COPY --chmod=755 netbird /usr/local/bin/netbird
