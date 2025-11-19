BINARY_NAME=sandworm
VERSION=latest

.PHONY: build test clean docker

build:
	go build -o $(BINARY_NAME) ./cmd/sandworm

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY_NAME)-linux-amd64 ./cmd/sandworm
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BINARY_NAME)-linux-arm64 ./cmd/sandworm

test:
	go test ./...

clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-linux-*

docker: build-linux
	./build-minimal-image.sh

run:
	go run ./cmd/sandworm --help