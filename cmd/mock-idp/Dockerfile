FROM golang:1.25-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/mock-idp ./cmd/mock-idp

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/mock-idp /mock-idp
USER 65532:65532
ENTRYPOINT ["/mock-idp"]
