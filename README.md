# GenAuth Agent Identity CLI

`genauth-agent` is the Node.js CLI for the complete GenAuth Agent Identity
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
npm install --global @eazo/genauth-agent-cli
genauth-agent version
genauth-agent --help
```

The npm package contains JavaScript plus the native Keychain adapter dependency;
there is no Go compiler, downloaded executable, platform subpackage, or
`postinstall` binary fetch.

## First journey

Tenant administrator login also selects a user pool:

```bash
genauth-agent --endpoint https://genauth.example.com auth login \
  --admin --profile-name agent-admin
```

A user login always binds to their own identity and one user pool:

```bash
genauth-agent --endpoint https://genauth.example.com auth login \
  --user-pool-id pool-id --profile-name agent-user
```

The CLI discovers the dedicated public OIDC login client from GenAuth at
`/api/v3/agent-identity/auth/config`, then opens the default GenAuth login page
and completes Authorization Code + PKCE S256 through a one-time loopback
callback. `--client-id` remains only as a hidden compatibility override for
older development environments.

Continue with discoverable help or the companion Skills:

```bash
genauth-agent permissions scopes
genauth-agent agents create --help
genauth-agent agents capability submit --help
genauth-agent approvals list
genauth-agent credentials create --help
genauth-agent authorizations create --help
genauth-agent tokens issue --help
genauth-agent providers call --help
```

Machine consumers should use the stable JSON envelope (the default), whose API
version remains `genauth-agent.cli/v1`. The canonical command contract is
`genauth-agent.commands/v2`; export it with `npm run contract:export`.

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
make acceptance-gates
```

`make verify` type-checks, runs unit/integration/contract tests, builds from a
clean `dist`, exports commands/v2, verifies version metadata and the npm tarball,
and checks the sibling `../genauth-agent-skill` repository. `make npm-smoke`
performs a real `npm pack`, installs the tarball into an isolated prefix, and
executes `genauth-agent version` and `--help`.

`make acceptance-gates` adds the full three-actor journey through an isolated
global installation of the packed npm tarball. The CLI uses the native
operating-system credential store through its Node.js Keychain dependency.

## GitLab CI to GitHub

The repository's [`.gitlab-ci.yml`](.gitlab-ci.yml) synchronizes commits on the
GitLab default branch and Git tags to the configured GitHub repository.

The sync job never force-pushes and never places the GitHub token in a remote
URL. Configure these GitLab CI/CD variables:

| Variable | Requirement |
| --- | --- |
| `GITHUB_TOKEN` | Masked and protected; a fine-grained token with `Contents: Read and write` on the target repository |
| `AGENT_CLI_GITHUB_REPOSITORY` | Required `owner/repository` value, for example `EazoAI/Genauth-Agent-CLI` |
| `GITHUB_TARGET_BRANCH` | Optional GitHub branch name; defaults to the GitLab default branch name |

Protect the GitLab default branch and every mirrored tag pattern so protected
variables are available to the job. If the GitHub branch has diverged, or a tag
with the same name points at a different commit, synchronization fails safely
and requires manual reconciliation.

### Publish to npm from GitLab

Every default-branch and release-tag pipeline first runs `verify_cli`. After it
passes, `publish_npm` is available as a manual job. The job validates npm
authentication, rejects a Tag/version mismatch or an existing package version,
rebuilds the package, reruns the release metadata and tarball checks, and then
publishes the public package to npmjs.org.

Configure `NPM_TOKEN` as a masked, protected, raw GitLab CI/CD variable. The
token must be allowed to publish `@eazo/genauth-agent-cli` and must satisfy
the npm account or organization 2FA policy. Protect release Tag patterns so the
variable is available to Tag pipelines. The temporary project `.npmrc` is
removed after every publish attempt.

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
- `src/storage`: local profiles and the operating-system Keychain adapter.
- `tests`: unit, management/runtime integration, and command contract tests.
- `scripts`: contract, Skill, package, smoke, and release verification.

The companion Skills are maintained in the sibling `genauth-agent-skill`
repository and call only this CLI's JSON interface.
