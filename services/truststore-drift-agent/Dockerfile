# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/truststore-drift-agent .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/truststore-drift-agent /truststore-drift-agent
USER nonroot
ENTRYPOINT ["/truststore-drift-agent"]
