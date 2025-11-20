FROM alpine:3.22.2

RUN apk add --no-cache ca-certificates
RUN update-ca-certificates

RUN addgroup -g 1001 -S sandworm && \
    adduser -S -D -H -u 1001 -s /sbin/nologin -G sandworm sandworm

# Copy the pre-built binary based on target architecture
# TARGETARCH is amd64 or arm64, but our binaries use the same naming
ARG TARGETARCH
COPY sandworm-linux-${TARGETARCH} /usr/local/bin/sandworm

# Make sure the binary is executable
RUN chmod +x /usr/local/bin/sandworm

USER sandworm
