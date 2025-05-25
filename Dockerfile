# Build stage
FROM golang:1.24 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o enigma-agent ./cmd/enigma-agent

# Runtime stage
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Install prerequisites, Zeek repo, Zeek, and nginx
RUN apt-get update && \
    apt-get install -y curl gpg nginx tcpdump && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg && \
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" | tee /etc/apt/sources.list.d/security:zeek.list && \
    apt-get update && \
    apt-get install -y zeek && \
    rm -rf /var/lib/apt/lists/*

# Add agent binary and default config
COPY --from=builder /app/enigma-agent /usr/local/bin/enigma-agent
COPY config.example.json /etc/enigma-agent/config.json

# Entry script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN ls -l /

EXPOSE 80

CMD ["/entrypoint.sh"]
