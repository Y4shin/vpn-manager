FROM golang:1.25-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/vpn-manager ./cmd/vpn-manager

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/vpn-manager /vpn-manager
USER 0:0
ENTRYPOINT ["/vpn-manager", "--config", "/etc/vpn-manager/config.yaml"]
