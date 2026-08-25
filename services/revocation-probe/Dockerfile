# syntax=docker/dockerfile:1
#
# Deliberately NOT distroless: profiles shell out to curl, openssl, and
# python3. See docs/adr/0006-alpine-over-distroless-for-probe.md and
# SECURITY.md for the reasoning and the compensating controls (non-root
# user, no added capability in the continuous service, image scanned in CI).
FROM golang:1.26.7-alpine3.23@sha256:b17af760035fc2f338eed92d448a6c67f2d45438844fc6c60678fa5f99e44b57 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/probe ./cmd/probe

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
# The base image is digest-pinned. Alpine repository packages remain a
# rebuild-time input until a package snapshot mirror is introduced.
# hadolint ignore=DL3018
RUN apk add --no-cache curl openssl python3 py3-requests ca-certificates \
    && addgroup -g 10001 -S probe && adduser -S -D -H -u 10001 -G probe probe
COPY --from=builder /out/probe /usr/local/bin/probe
COPY profiles.yaml /etc/pki-sentinel/profiles.yaml
COPY scenarios /etc/pki-sentinel/scenarios
WORKDIR /etc/pki-sentinel
# hadolint ignore=DL3066
USER probe
EXPOSE 9110
ENTRYPOINT ["probe"]
CMD ["run", "--config", "/etc/pki-sentinel/profiles.yaml"]
