# syntax=docker/dockerfile:1
#
# Deliberately NOT distroless: profiles shell out to curl, openssl, python3,
# and tc. See docs/adr/0006-alpine-over-distroless-for-probe.md and
# SECURITY.md for the reasoning and the compensating controls (non-root
# user, capability scoped to CAP_NET_ADMIN only, image scanned in CI).
FROM golang:1.26.6-alpine3.23 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/probe ./cmd/probe

FROM alpine:3.23
# Exact apk revisions are intentionally inherited from the pinned Alpine
# repository snapshot represented by the base image tag.
# hadolint ignore=DL3018
RUN apk add --no-cache curl openssl python3 py3-requests iproute2 ca-certificates libcap \
    && addgroup -S probe && adduser -S probe -G probe
COPY --from=builder /out/probe /usr/local/bin/probe
# `tc` needs CAP_NET_ADMIN even when the container itself has it via
# cap_add, because that grant applies to the root process, not arbitrary
# non-root users. File capabilities on the tc binary let the non-root
# `probe` user invoke it without running the whole process as root.
RUN setcap cap_net_admin=+ep /sbin/tc
COPY profiles.yaml /etc/pki-sentinel/profiles.yaml
WORKDIR /etc/pki-sentinel
# hadolint ignore=DL3066
USER probe
EXPOSE 9110
ENTRYPOINT ["probe"]
CMD ["run", "--config", "/etc/pki-sentinel/profiles.yaml"]
