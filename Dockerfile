# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/vulnhound ./cmd/vulnhound

# Final minimal scratch runtime
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="NoneLabs VulnHound Community" \
      org.opencontainers.image.description="Zero-Cloud, Self-Contained Vulnerability Intelligence (CVE/CWE RAG & Secret Ops)" \
      org.opencontainers.image.authors="limmireu1214@gmail.com" \
      org.opencontainers.image.licenses="LGPL-3.0"

WORKDIR /app

COPY --from=builder /bin/vulnhound /usr/local/bin/vulnhound
COPY data /data

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/vulnhound"]
CMD ["help"]
