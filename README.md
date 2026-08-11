# GenAuth Agent Identity CLI

`agent-identity` is the Node.js CLI for the complete GenAuth Agent Identity
journey. It authenticates a tenant administrator or user, selects one user
pool, creates and approves company Agents, manages Agent-level settings and
Credentials, completes explicit or policy-allowed silent authorization, issues
Agent access Tokens, and calls fixed Provider routes through GenAuth.

The CLI calls only the configured GenAuth public endpoint. It never calls Agent
Identity private service routes, EAK Delegation, or Token Vault directly.

## Requirements and installation

- Node.js 22.22 or newer (Node 24 is also tested).
- macOS arm64/x64, Linux arm64/x64, or Windows x64.
- An operating-system secret store available to the current desktop/session.

Install globally from npm after the package is published:

```bash
npm install --global @authing/agent-identity-cli
agent-identity version
agent-identity --help
```

The npm package contains JavaScript plus the native Keychain adapter dependency;
there is no Go compiler, downloaded executable, platform subpackage, or
`postinstall` binary fetch.

## First journey

Tenant administrator login also selects a user pool:

```bash
agent-identity --endpoint https://genauth.example.com auth login \
  --admin --client-id your-client-id --user-pool-id pool-id
```

A user login always binds to their own identity and one user pool:

```bash
agent-identity --endpoint https://genauth.example.com auth login \
  --client-id your-client-id --user-pool-id pool-id
```

Continue with discoverable help or the companion Skills:

```bash
agent-identity permissions scopes
agent-identity agents create --help
agent-identity agents capability submit --help
agent-identity approvals list
agent-identity credentials create --help
agent-identity authorizations create --help
agent-identity tokens issue --help
agent-identity providers call --help
```

Machine consumers should use the stable JSON envelope (the default), whose API
version remains `agent-identity.cli/v1`. The canonical command contract is
`agent-identity.commands/v2`; export it with `npm run contract:export`.

## Security boundary

- Every profile is scoped to one explicitly selected user pool.
- Login refresh tokens, PKCE verifiers, authorization codes, and Agent
  Credential secrets live in the operating-system keyring, never in the profile
  file.
- Secret and Token material is hidden unless the command has an explicit
  acknowledgement. Runtime Tokens passed to child processes use environment
  variables rather than command-line arguments.
- Administrator silent authorization requires confirmation and server policy;
  users can authorize only themselves with explicit consent.
- Provider calls are restricted to GenAuth's fixed forwarding route and reject
  absolute or traversal paths.
- HTTP is accepted only for localhost with `--allow-insecure-localhost`. Custom
  CA files extend, rather than replace, system roots. Proxy URLs cannot contain
  credentials or paths.

GenAuth remains the public ingress and Provider forwarding layer. Agent Identity
owns authorization state and Agent access-token signing. Permission definitions
remain in the upstream permission system; Agent Identity stores snapshots.

## Develop and verify

```bash
npm ci
make verify
make npm-smoke
make migration-gates
```

`make verify` type-checks, runs unit/integration/contract tests, builds from a
clean `dist`, exports commands/v2, verifies version metadata and the npm tarball,
and checks the sibling `../genauth-agent-skill` repository. `make npm-smoke`
performs a real `npm pack`, installs the tarball into an isolated prefix, and
executes `agent-identity version` and `--help`.

`make migration-gates` additionally builds the annotated Go baseline and
compares every mapped leaf command, error exit, HTTP request and JSON envelope;
it also proves bidirectional Go/Node Keychain compatibility and runs the full
three-actor journey through an isolated global install of the packed npm
tarball. The local Keychain gate uses the current operating system's secure
store.

CI repeats the Keychain test against macOS Keychain, Linux Secret Service, and
Windows Credential Manager. The Windows adapter deliberately preserves Go's
`agent-identity-cli:<account>` target, raw UTF-8 blob, username, and local-machine
persistence instead of using the native dependency's incompatible defaults.

The GitHub verify workflow runs Node 22 and 24 across macOS arm64/x64, Linux
arm64/x64, and Windows x64. The release workflow publishes one npm package with
provenance and attaches that tarball plus checksums to the GitHub release only
after the platform matrix, platform Keychain compatibility, Go/Node
differential, installed journey, and Skill contract jobs all pass.

## Release

```bash
node scripts/set-version.mjs 0.2.0
make verify
make npm-smoke
make release-pack
```

Push the matching tag (for example `v0.2.0`) after CI passes. Configure npm
trusted publishing or `NPM_TOKEN` before the first release. Package metadata is
currently `UNLICENSED`; choose and add a license before publishing as public
open-source software.

## Source layout

- `src/bin`: executable entrypoint and stable failure handling.
- `src/cli`: commands/v2 registry and journey orchestration.
- `src/auth`: OIDC PKCE, browser callback, refresh, and revocation.
- `src/http`: bounded, retry-aware GenAuth HTTP transport.
- `src/storage`: Go-compatible profile and operating-system Keychain adapters.
- `tests`: unit, management/runtime integration, and command contract tests.
- `scripts`: contract, Skill, package, smoke, and release verification.

The companion Skills are maintained in the sibling `genauth-agent-skill`
repository and call only this CLI's JSON interface.
