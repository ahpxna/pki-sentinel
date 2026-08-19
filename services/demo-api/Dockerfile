# syntax=docker/dockerfile:1
FROM golang:1.26.6-alpine3.23 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/demo-api .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/demo-api /demo-api
# hadolint ignore=DL3066
USER nonroot
EXPOSE 8000
ENTRYPOINT ["/demo-api"]
