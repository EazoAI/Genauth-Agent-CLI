# Agent Identity CLI

This package installs the `agent-identity` command used to manage the GenAuth
Agent Identity lifecycle. npm selects a platform-specific package containing
the signed, prebuilt Go executable; a Go toolchain is not required.

```bash
npm install --global @authing/agent-identity-cli
agent-identity version
agent-identity --help
```

Do not install with `--omit=optional`: the matching platform binary is an
optional dependency so npm can skip packages for other operating systems.

Supported platforms are macOS arm64/x64, Linux arm64/x64, and Windows x64.
