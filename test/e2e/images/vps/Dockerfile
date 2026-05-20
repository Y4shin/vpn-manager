FROM golang:1.25-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/vpn-manager ./cmd/vpn-manager

FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iproute2 sqlite tcpdump iputils
COPY --from=build /out/vpn-manager /usr/local/bin/vpn-manager
ENTRYPOINT ["/usr/local/bin/vpn-manager", "--config", "/etc/vpn-manager/config.yaml"]
