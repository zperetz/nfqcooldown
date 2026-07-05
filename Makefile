BINARY=nfqcooldown
OUT=./bin/$(BINARY)

.PHONY: build clean install

VERSION ?= dev

build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-ldflags="-X main.Version=$(VERSION)" \
		-o $(OUT) ./cmd/nfqcooldown

clean:
	rm -rf ./bin

install: build
	install -m 0755 $(OUT) /usr/local/sbin/nfqcooldown
