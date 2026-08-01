# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/demo-api .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/demo-api /demo-api
USER nonroot
EXPOSE 8000
ENTRYPOINT ["/demo-api"]
