FROM golang:1.25-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/login-and-fetch ./cmd/login-and-fetch

FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iproute2 iputils curl jq
COPY --from=build /out/login-and-fetch /usr/local/bin/login-and-fetch
ENTRYPOINT ["sleep", "infinity"]
