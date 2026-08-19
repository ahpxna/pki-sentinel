# syntax=docker/dockerfile:1
FROM golang:1.26.6-alpine3.23 AS builder
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/truststore-drift-agent .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/truststore-drift-agent /truststore-drift-agent
# hadolint ignore=DL3066
USER nonroot
ENTRYPOINT ["/truststore-drift-agent"]
