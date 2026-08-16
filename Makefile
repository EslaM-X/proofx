.PHONY: build test vet lint fmt install proof verify

build:
	go build -o bin/proofx ./cmd/proofx

test:
	go test -race -cover ./...

vet:
	go vet ./...

lint:
	golangci-lint run --timeout=5m

fmt:
	gofmt -w .

install:
	go install github.com/EslaM-X/proofx/cmd/proofx@latest

proof:
	go run ./cmd/proofx collect && go run ./cmd/proofx prove

verify:
	go run ./cmd/proofx verify proof.json
