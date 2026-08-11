SHELL := /bin/sh

.PHONY: help install clean check test coverage build metadata-check skills-check pack-check npm-smoke differential e2e keychain-compat migration-gates release-pack verify

help:
	@echo "install        Install the CLI globally from this checkout"
	@echo "clean          Remove generated dist output"
	@echo "check          Type-check all source, scripts, and tests"
	@echo "test           Run the Vitest suite"
	@echo "coverage       Run tests with coverage"
	@echo "build          Compile the Node.js CLI"
	@echo "metadata-check Verify synchronized release metadata"
	@echo "skills-check   Verify the sibling Skills against commands/v2"
	@echo "pack-check     Inspect the npm tarball manifest"
	@echo "npm-smoke      Pack, install, and execute the npm package"
	@echo "differential   Compare the complete Go baseline and Node CLI contracts"
	@echo "e2e            Run the npm-installed multi-actor Agent journey"
	@echo "keychain-compat Prove bidirectional compatibility with the Go OS keyring"
	@echo "migration-gates Run all local migration acceptance gates"
	@echo "release-pack   Create the npm GitHub release artifact"
	@echo "verify         Run all local non-install verification gates"

install: build
	npm install --global .

clean:
	npm run clean

check:
	npm run check

test:
	npm test

coverage:
	npm run test:coverage

build:
	npm run build
	npm run contract:export

metadata-check:
	npm run metadata:check

skills-check: build
	npm run skills:verify

pack-check: build metadata-check
	npm run pack:check

npm-smoke: build metadata-check
	npm run smoke:npm

differential:
	npm run test:differential

e2e:
	npm run test:e2e

keychain-compat:
	npm run test:keychain-compat

migration-gates: verify differential e2e keychain-compat npm-smoke

release-pack: verify
	./scripts/package-github-release.sh

verify:
	npm run verify
	npm run skills:verify
