# GenAuth Agent Identity CLI

`agent-identity` is the user-facing CLI for the GenAuth Agent Identity lifecycle.
It talks only to the configured GenAuth public endpoint; it never calls Agent
Identity private service routes directly.

## Security boundary

- Administrator and member profiles are scoped to one selected user pool.
- Login refresh tokens, PKCE verifiers, authorization codes, and Agent
  Credential secrets are stored in the operating-system keyring.
- JSON is the stable automation format. Secret and Token material is omitted
  unless an explicitly confirmed command requires it.
- GenAuth remains the public ingress and Provider forwarding layer. Agent
  Identity owns authorization state and Agent access-token signing.

## Build and verify

```bash
make verify
./bin/agent-identity --help
```

## Install with npm

End users do not need a Go toolchain. The public npm launcher installs the
matching prebuilt platform package and exposes the existing command:

```bash
npm install --global @authing/agent-identity-cli
agent-identity version
agent-identity --help
```

The npm launcher does not download executables in a `postinstall` hook. npm
selects one package using its `os` and `cpu` metadata. Do not install with
`--omit=optional`, because the platform package is intentionally declared as an
optional dependency so packages for other platforms can be skipped.

Supported targets:

- macOS arm64 and x64
- Linux arm64 and x64
- Windows x64

Go developers may still install directly from source:

```bash
make install
```

## Prepare a release

Update all Go and npm version metadata, verify, and build the distributable
artifacts:

```bash
node scripts/set-version.mjs 0.2.0
make verify
make test-race
make npm-smoke
make release-pack
```

`make npm-smoke` packs the launcher and current platform package, installs both
globally into an isolated temporary npm prefix, and executes
`agent-identity version`.
`make release-pack` creates the five platform binaries, GitHub archives, and
`SHA256SUMS` under `dist/release`.

Pushing a matching tag such as `v0.2.0` runs the GitHub release workflow. The
workflow validates the tag against `VERSION`, publishes all platform packages
before the launcher package, and creates a GitHub Release. Configure an npm
automation token as the repository secret `NPM_TOKEN` before the first release.

The package metadata currently uses `UNLICENSED`; choose and add the repository
license before publishing it as public open-source software.

## Source layout

- `cmd/agent-identity`: executable entrypoint.
- `internal/cli/apiclient`: bounded, retry-aware GenAuth HTTP client.
- `internal/cli/authflow`: browser login, refresh, revoke, and PKCE helpers.
- `internal/cli/command`: command tree and user-journey orchestration.
- `internal/cli/profile`: non-secret profile persistence.
- `internal/cli/secretstore`: operating-system keyring adapter.
- `npm/agent-identity-cli`: dependency-free Node launcher published to npm.
- `npm/platforms`: OS/CPU-specific packages populated during release builds.
- `scripts`: version synchronization, cross-compilation, packaging, and smoke
  tests.

The companion Skills are maintained separately in the sibling
`genauth-agent-skill` source directory.
