BINARY := cargo-scanner
CMD := ./cmd/cargo-scanner

.PHONY: test build doctor release-snapshot docker-build clean

test:
	go test ./...

build:
	go build -trimpath -ldflags "-s -w" -o bin/$(BINARY) $(CMD)

doctor: build
	./bin/$(BINARY) doctor

release-snapshot:
	goreleaser release --snapshot --clean

docker-build:
	docker build -t cargo-scanner-runtime:local -f docker/Dockerfile .

clean:
	rm -rf bin dist
