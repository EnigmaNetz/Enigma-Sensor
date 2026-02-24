# Stage 1: builder
# golang:1.24-bookworm provides Go 1.24 on Debian Bookworm (amd64)
# libpcap-dev is required at build time for github.com/google/gopacket (CGO)
FROM golang:1.24-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy dependency files first to leverage layer caching.
# Module downloads are re-used when only application code changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy full source and compile a statically linked binary for linux/amd64.
# CGO_ENABLED=1 is required by gopacket which wraps libpcap via cgo.
COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -o enigma-sensor ./cmd/enigma-sensor


# Stage 2: runtime
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install base runtime dependencies.
# tcpdump: packet capture on Linux
# ca-certificates: TLS root CAs for gRPC connections to the Enigma API
# curl, gnupg: used to add the OpenSUSE Zeek repository key and list
# libpcap0.8: shared library required by the CGO-linked enigma-sensor binary
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tcpdump \
        ca-certificates \
        curl \
        gnupg \
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Install Zeek from the official OpenSUSE security repository for Ubuntu 22.04.
# This matches the pattern used in loadtest/Dockerfile.sensor.
# Pin Zeek to 8.0.5 to avoid breaking changes from new releases
RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
        | gpg --dearmor \
        | tee /etc/apt/trusted.gpg.d/security_zeek.gpg \
    && echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
        | tee /etc/apt/sources.list.d/security:zeek.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends zeek=8.0.5-0 \
    && rm -rf /var/lib/apt/lists/*

# Create runtime directories used by the sensor.
# /etc/enigma-sensor     config files (config.json mounted here at runtime)
# /var/log/enigma-sensor log output
# /var/lib/enigma-sensor/captures PCAP working directory
RUN mkdir -p \
        /etc/enigma-sensor \
        /var/log/enigma-sensor \
        /var/lib/enigma-sensor/captures

# Copy compiled binary from the builder stage.
COPY --from=builder /src/enigma-sensor /usr/local/bin/enigma-sensor

# Copy Zeek scripts used by the processor for sampling and log generation.
COPY zeek-scripts/ /app/zeek-scripts/

# Copy the example config as a template; operators mount or override config.json
# at /etc/enigma-sensor/config.json to supply API keys and settings.
COPY config.example.json /etc/enigma-sensor/config.template.json

# Copy and enable the container entrypoint.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /app

# Packet capture requires CAP_NET_RAW and CAP_NET_ADMIN.
# Running as root is the simplest way to satisfy this; operators should grant
# only the required capabilities (--cap-add NET_RAW --cap-add NET_ADMIN)
# and consider using a non-root user with file capabilities in hardened envs.
USER root

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/enigma-sensor"]
