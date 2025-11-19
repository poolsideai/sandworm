#!/bin/bash
set -euo pipefail

# Build minimal sandworm binary and multiarch Docker image
# This script produces compressed, stripped binaries and a multiarch Docker image

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}"
BUILD_DIR="${SCRIPT_DIR}/cmd/sandworm"
IMAGE_NAME="sandworm"

echo "Building minimal sandworm binaries and Docker image for amd64 and arm64..."

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

# Build for both architectures
ARCHS=("amd64" "arm64")

for ARCH in "${ARCHS[@]}"; do
    echo "Step 1: Building optimized binary for ${ARCH}..."
    GOARCH="${ARCH}" GOOS=linux go build \
        -ldflags="-s -w" \
        -trimpath \
        -o "${OUTPUT_DIR}/sandworm-linux-${ARCH}" \
        "${BUILD_DIR}"
    
    echo "Step 2: Compressing with UPX for ${ARCH}..."
    # Check if upx is available
    if ! command -v upx &> /dev/null; then
        echo "Warning: upx not found, skipping compression for ${ARCH}"
        echo "Binary size (${ARCH}): $(du -h "${OUTPUT_DIR}/sandworm-linux-${ARCH}" | cut -f1)"
    else
        if upx --best --quiet "${OUTPUT_DIR}/sandworm-linux-${ARCH}" 2>/dev/null; then
            echo "Compressed binary size (${ARCH}): $(du -h "${OUTPUT_DIR}/sandworm-linux-${ARCH}" | cut -f1)"
        else
            echo "Binary already compressed or UPX failed for ${ARCH}"
            echo "Binary size (${ARCH}): $(du -h "${OUTPUT_DIR}/sandworm-linux-${ARCH}" | cut -f1)"
        fi
    fi
done

echo "Step 3: Testing binaries..."
# Test the binary that matches current architecture
CURRENT_ARCH=$(uname -m)
if [[ "${CURRENT_ARCH}" == "x86_64" ]]; then
    TEST_ARCH="amd64"
elif [[ "${CURRENT_ARCH}" == "aarch64" ]]; then
    TEST_ARCH="arm64"
else
    echo "Warning: Unknown architecture ${CURRENT_ARCH}, testing amd64 binary"
    TEST_ARCH="amd64"
fi

"${OUTPUT_DIR}/sandworm-linux-${TEST_ARCH}" --help > /dev/null
echo "✓ Binary test passed for ${TEST_ARCH}"

echo "✓ Minimal binaries created:"
for ARCH in "${ARCHS[@]}"; do
    echo "  - ${OUTPUT_DIR}/sandworm-linux-${ARCH}"
done

echo ""
echo "Step 4: Building multiarch Docker image..."

# Check if docker buildx is available
if ! docker buildx version &> /dev/null; then
    echo "Error: docker buildx is required but not available"
    exit 1
fi

# Create a new builder instance if it doesn't exist
BUILDER_NAME="multiarch-builder"
if ! docker buildx ls | grep -q "${BUILDER_NAME}"; then
    echo "Creating buildx builder instance: ${BUILDER_NAME}"
    docker buildx create --name "${BUILDER_NAME}" --use
else
    echo "Using existing buildx builder instance: ${BUILDER_NAME}"
    docker buildx use "${BUILDER_NAME}"
fi

# Build multiarch image using the local binaries
# Build from the script directory
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --tag "${IMAGE_NAME}:latest" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${SCRIPT_DIR}"

docker buildx build --load --tag "${IMAGE_NAME}:latest" -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}"


echo "✓ Multiarch Docker image created: ${IMAGE_NAME}:latest"
echo "  - Supports: linux/amd64, linux/arm64"