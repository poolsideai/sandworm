FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the pre-built binary based on target architecture
# TARGETARCH is amd64 or arm64, but our binaries use the same naming
ARG TARGETARCH
COPY sandworm-linux-${TARGETARCH} /usr/local/bin/sandworm

# Make sure the binary is executable
RUN chmod +x /usr/local/bin/sandworm