FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.mod ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o vault ./cmd/vault

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -g 1000 vault && adduser -u 1000 -G vault -s /sbin/nologin -D vault

WORKDIR /app
COPY --from=builder --chown=vault:vault /build/vault .

USER vault
EXPOSE 8443

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
    CMD wget -qO- http://localhost:8443/health || exit 1

ENTRYPOINT ["./vault"]
