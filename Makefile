SHELL := /bin/sh
GO_FILES := $$(find . -name '*.go')

.PHONY: help format test test-race vet build install metadata-check npm-test release-build release-pack npm-smoke verify

help:
	@echo "format      Format Go source"
	@echo "test        Run unit tests"
	@echo "test-race   Run race-enabled tests"
	@echo "vet         Run go vet"
	@echo "build       Build bin/agent-identity"
	@echo "install     Install agent-identity with go install"
	@echo "metadata-check Check Go and npm package versions"
	@echo "npm-test    Test the npm launcher"
	@echo "release-build Build all npm platform binaries"
	@echo "release-pack Build npm and GitHub release artifacts"
	@echo "npm-smoke   Install the local npm packages and run the CLI"
	@echo "verify      Format, test, vet, build, and test the npm launcher"

format:
	gofmt -w $(GO_FILES)

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -trimpath -o bin/agent-identity ./cmd/agent-identity

install:
	go install ./cmd/agent-identity

metadata-check:
	node ./scripts/verify-release-metadata.mjs

npm-test:
	npm --prefix npm test

release-build:
	./scripts/build-release.sh
	node ./scripts/stage-npm-packages.mjs

release-pack: release-build
	./scripts/package-github-release.sh

npm-smoke: release-build
	node ./scripts/smoke-npm-install.mjs

verify: format test vet build metadata-check npm-test
